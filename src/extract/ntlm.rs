//! NTLM hashes from SAM registry hives and plain hash lists.

use pgp::crypto::hash::HashAlgorithm;

use super::hashlist::{extract_from_data, probe_data};
use super::{Artifact, CompanionSpec, ExtractError, Extracted, Extractor, Probe};
use crate::types::Ntlm;
use crate::{HashType, HashValue};

const REGF: &[u8] = b"regf";
const HBIN: &[u8] = b"hbin";
const HIVE_BINS_START: usize = 0x1000;
const HBIN_HEADER: usize = 0x20;
const NIL: u32 = 0xffff_ffff;
const NT_HASH_OFFSET: usize = 0xa8;
const NT_HASH_LENGTH: usize = 0xac;
const USER_DATA_START: usize = 0xcc;
const QWERTY: &[u8] = b"!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0";
const DIGITS: &[u8] = b"0123456789012345678901234567890123456789\0";
const NTPASSWORD: &[u8] = b"NTPASSWORD\0";

fn invalid(message: impl Into<String>) -> ExtractError {
    ExtractError::Invalid(message.into())
}

fn unsupported(message: impl Into<String>) -> ExtractError {
    ExtractError::Unsupported(message.into())
}

fn u16_at(data: &[u8], offset: usize) -> Result<u16, ExtractError> {
    let bytes = data
        .get(offset..offset + 2)
        .ok_or_else(|| invalid("truncated registry cell"))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn u32_at(data: &[u8], offset: usize) -> Result<u32, ExtractError> {
    let bytes = data
        .get(offset..offset + 4)
        .ok_or_else(|| invalid("truncated registry cell"))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn decode_ascii(bytes: &[u8]) -> Result<String, ExtractError> {
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| invalid("registry name is not ASCII"))
}

fn decode_utf16(bytes: &[u8]) -> Result<String, ExtractError> {
    if bytes.len() % 2 != 0 {
        return Err(invalid("registry string has an odd byte length"));
    }
    let mut units = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        units.push(u16::from_le_bytes([pair[0], pair[1]]));
    }
    let value =
        String::from_utf16(&units).map_err(|_| invalid("registry string is not valid UTF-16"))?;
    Ok(value.trim_end_matches('\0').to_owned())
}

struct Key {
    subkey_count: u32,
    subkey_list: u32,
    value_count: u32,
    value_list: u32,
    class_offset: u32,
    class_length: u16,
    name: String,
}

struct Value {
    name: String,
    data: Vec<u8>,
}

struct Hive<'a> {
    data: &'a [u8],
    bins: Vec<(usize, usize)>,
    root: u32,
}

impl<'a> Hive<'a> {
    fn parse(data: &'a [u8]) -> Result<Self, ExtractError> {
        if data.len() < HIVE_BINS_START || &data[..4] != REGF {
            return Err(unsupported("not a registry hive"));
        }
        let major = u32_at(data, 0x10)?;
        if major != 1 {
            return Err(invalid("unsupported registry hive version"));
        }
        let root = u32_at(data, 0x20)?;
        let bins_size = u32_at(data, 0x24)? as usize;
        if root == NIL || bins_size == 0 {
            return Err(invalid("registry hive has no root cell or hive bins"));
        }
        let bins_end = HIVE_BINS_START
            .checked_add(bins_size)
            .filter(|end| *end <= data.len())
            .ok_or_else(|| invalid("registry hive bins extend past the artifact"))?;

        let mut bins = Vec::new();
        let mut start = HIVE_BINS_START;
        while start < bins_end {
            if start + HBIN_HEADER > bins_end || data.get(start..start + 4) != Some(HBIN) {
                return Err(invalid("invalid registry hive bin header"));
            }
            let relative = u32_at(data, start + 4)? as usize;
            if relative != start - HIVE_BINS_START {
                return Err(invalid("registry hive bin offset mismatch"));
            }
            let size = u32_at(data, start + 8)? as usize;
            if size < 0x1000 || size % 0x1000 != 0 || start + size > bins_end {
                return Err(invalid("invalid registry hive bin size"));
            }
            bins.push((start, start + size));
            start += size;
        }
        if start != bins_end {
            return Err(invalid("registry hive bins do not fill the declared size"));
        }

        let hive = Self { data, bins, root };
        let root_key = hive.key(root)?;
        if root_key.name.is_empty() {
            return Err(invalid("registry hive root key has no name"));
        }
        Ok(hive)
    }

    fn cell(&self, offset: u32) -> Result<&'a [u8], ExtractError> {
        let position = HIVE_BINS_START
            .checked_add(offset as usize)
            .ok_or_else(|| invalid("registry cell offset overflows"))?;
        let (_, end) = self
            .bins
            .iter()
            .copied()
            .find(|(start, end)| position >= *start + HBIN_HEADER && position < *end)
            .ok_or_else(|| invalid("registry cell offset is outside the hive bins"))?;
        if position + 4 > end {
            return Err(invalid("truncated registry cell header"));
        }
        let size = i32::from_le_bytes([
            self.data[position],
            self.data[position + 1],
            self.data[position + 2],
            self.data[position + 3],
        ]);
        if size >= 0 {
            return Err(invalid("registry cell is not allocated"));
        }
        let length = size.unsigned_abs() as usize;
        if length < 4 || position + length > end {
            return Err(invalid("invalid registry cell size"));
        }
        Ok(&self.data[position + 4..position + length])
    }

    fn key(&self, offset: u32) -> Result<Key, ExtractError> {
        let cell = self.cell(offset)?;
        if cell.len() < 0x4c || &cell[..2] != b"nk" {
            return Err(invalid("registry cell is not a key node"));
        }
        let flags = u16_at(cell, 2)?;
        let name_length = u16_at(cell, 0x48)? as usize;
        let name = cell
            .get(0x4c..0x4c + name_length)
            .ok_or_else(|| invalid("truncated registry key name"))?;
        let name = if flags & 0x20 != 0 {
            decode_ascii(name)?
        } else {
            decode_utf16(name)?
        };
        Ok(Key {
            subkey_count: u32_at(cell, 0x14)?,
            subkey_list: u32_at(cell, 0x1c)?,
            value_count: u32_at(cell, 0x24)?,
            value_list: u32_at(cell, 0x28)?,
            class_offset: u32_at(cell, 0x30)?,
            class_length: u16_at(cell, 0x4a)?,
            name,
        })
    }

    fn class_name(&self, key: &Key) -> Result<String, ExtractError> {
        if key.class_length == 0 || key.class_offset == NIL {
            return Ok(String::new());
        }
        let cell = self.cell(key.class_offset)?;
        let length = key.class_length as usize;
        let bytes = cell
            .get(..length)
            .ok_or_else(|| invalid("truncated registry class name"))?;
        decode_utf16(bytes)
    }

    fn subkeys(&self, key: &Key) -> Result<Vec<u32>, ExtractError> {
        if key.subkey_count == 0 {
            return Ok(Vec::new());
        }
        if key.subkey_list == NIL {
            return Err(invalid("registry key has no subkey list"));
        }
        let mut offsets = Vec::new();
        self.collect_subkeys(key.subkey_list, 0, &mut offsets)?;
        if offsets.len() != key.subkey_count as usize {
            return Err(invalid("registry subkey count does not match its list"));
        }
        Ok(offsets)
    }

    fn collect_subkeys(
        &self,
        offset: u32,
        depth: usize,
        offsets: &mut Vec<u32>,
    ) -> Result<(), ExtractError> {
        if depth > 8 || offsets.len() > 1_000_000 {
            return Err(invalid("registry subkey list is too deeply nested"));
        }
        let cell = self.cell(offset)?;
        if cell.len() < 4 {
            return Err(invalid("truncated registry subkey list"));
        }
        let count = u16_at(cell, 2)? as usize;
        match &cell[..2] {
            b"lf" | b"lh" => {
                let entries = cell
                    .get(4..4 + count * 8)
                    .ok_or_else(|| invalid("truncated registry subkey list"))?;
                for entry in entries.chunks_exact(8) {
                    offsets.push(u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]));
                }
            }
            b"li" | b"ri" => {
                let entries = cell
                    .get(4..4 + count * 4)
                    .ok_or_else(|| invalid("truncated registry subkey list"))?;
                let nested = &cell[..2] == b"ri";
                for entry in entries.chunks_exact(4) {
                    let child = u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]);
                    if nested {
                        self.collect_subkeys(child, depth + 1, offsets)?;
                    } else {
                        offsets.push(child);
                    }
                }
            }
            _ => return Err(invalid("unknown registry subkey list type")),
        }
        Ok(())
    }

    fn values(&self, key: &Key) -> Result<Vec<Value>, ExtractError> {
        if key.value_count == 0 {
            return Ok(Vec::new());
        }
        if key.value_list == NIL {
            return Err(invalid("registry key has no value list"));
        }
        let cell = self.cell(key.value_list)?;
        let count = key.value_count as usize;
        let entries = cell
            .get(..count * 4)
            .ok_or_else(|| invalid("truncated registry value list"))?;
        let mut values = Vec::with_capacity(count);
        for entry in entries.chunks_exact(4) {
            let offset = u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]);
            values.push(self.value(offset)?);
        }
        Ok(values)
    }

    fn value(&self, offset: u32) -> Result<Value, ExtractError> {
        let cell = self.cell(offset)?;
        if cell.len() < 0x14 || &cell[..2] != b"vk" {
            return Err(invalid("registry cell is not a value node"));
        }
        let name_length = u16_at(cell, 2)? as usize;
        let data_length = u32_at(cell, 4)?;
        let data_offset = u32_at(cell, 8)?;
        let flags = u16_at(cell, 0x10)?;
        let name = cell
            .get(0x14..0x14 + name_length)
            .ok_or_else(|| invalid("truncated registry value name"))?;
        let name = if flags & 0x01 != 0 {
            decode_ascii(name)?
        } else {
            decode_utf16(name)?
        };
        let data = if data_length & 0x8000_0000 != 0 {
            let length = (data_length & 0x7fff_ffff) as usize;
            if length > 4 {
                return Err(invalid("inline registry value is too long"));
            }
            data_offset.to_le_bytes()[..length].to_vec()
        } else {
            let length = data_length as usize;
            if length == 0 {
                Vec::new()
            } else {
                let cell = self.cell(data_offset)?;
                cell.get(..length)
                    .ok_or_else(|| invalid("truncated registry value data"))?
                    .to_vec()
            }
        };
        Ok(Value { name, data })
    }

    fn find_child(&self, key: &Key, name: &str) -> Result<Option<Key>, ExtractError> {
        for offset in self.subkeys(key)? {
            let child = self.key(offset)?;
            if child.name.eq_ignore_ascii_case(name) {
                return Ok(Some(child));
            }
        }
        Ok(None)
    }

    fn find_path(&self, mut key: Key, path: &[&str]) -> Result<Option<Key>, ExtractError> {
        for name in path {
            let Some(child) = self.find_child(&key, name)? else {
                return Ok(None);
            };
            key = child;
        }
        Ok(Some(key))
    }
}

fn md5(parts: &[&[u8]]) -> Result<[u8; 16], ExtractError> {
    let mut hasher = HashAlgorithm::MD5
        .new_hasher()
        .map_err(|error| invalid(format!("cannot create MD5: {error}")))?;
    for part in parts {
        hasher.update(part);
    }
    hasher
        .finish()
        .try_into()
        .map_err(|_| invalid("unexpected MD5 length"))
}

fn rc4(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut state = [0u8; 256];
    for (index, byte) in state.iter_mut().enumerate() {
        *byte = index as u8;
    }
    let mut j = 0usize;
    for i in 0..256 {
        j = (j + state[i] as usize + key[i % key.len()] as usize) & 0xff;
        state.swap(i, j);
    }
    let mut i = 0usize;
    j = 0;
    data.iter()
        .map(|byte| {
            i = (i + 1) & 0xff;
            j = (j + state[i] as usize) & 0xff;
            state.swap(i, j);
            byte ^ state[(state[i] as usize + state[j] as usize) & 0xff]
        })
        .collect()
}

const IP: [u8; 64] = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61,
    53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
];
const FP: [u8; 64] = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
];
const E: [u8; 48] = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18,
    19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
];
const P: [u8; 32] = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19,
    13, 30, 6, 22, 11, 4, 25,
];
const PC1: [u8; 56] = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60,
    52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
];
const PC2: [u8; 48] = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52,
    31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
];
const SHIFTS: [u32; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];
const SBOX: [[u8; 64]; 8] = [
    [
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12,
        11, 9, 5, 3, 8, 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9,
        1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
    ],
    [
        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1,
        10, 6, 9, 11, 5, 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15,
        4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
    ],
    [
        10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5,
        14, 12, 11, 15, 1, 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6,
        9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
    ],
    [
        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2,
        12, 1, 10, 14, 9, 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1,
        13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
    ],
    [
        2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15,
        10, 3, 9, 8, 6, 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14,
        2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
    ],
    [
        12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13,
        14, 0, 11, 3, 8, 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5,
        15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
    ],
    [
        4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5,
        12, 2, 15, 8, 6, 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4,
        10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
    ],
    [
        13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6,
        11, 0, 14, 9, 2, 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10,
        8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
    ],
];

fn permute(input: u64, table: &[u8], input_bits: u32) -> u64 {
    let mut output = 0u64;
    for position in table {
        let bit = (input >> (input_bits - u32::from(*position))) & 1;
        output = (output << 1) | bit;
    }
    output
}

fn des_subkeys(key: u64) -> [u64; 16] {
    let selected = permute(key, &PC1, 64);
    let mut left = (selected >> 28) & 0x0fff_ffff;
    let mut right = selected & 0x0fff_ffff;
    let mut subkeys = [0u64; 16];
    for (index, shift) in SHIFTS.iter().enumerate() {
        left = ((left << shift) | (left >> (28 - shift))) & 0x0fff_ffff;
        right = ((right << shift) | (right >> (28 - shift))) & 0x0fff_ffff;
        subkeys[index] = permute((left << 28) | right, &PC2, 56);
    }
    subkeys
}

fn des_round(right: u32, subkey: u64) -> u32 {
    let expanded = permute(u64::from(right), &E, 32) ^ subkey;
    let mut substituted = 0u32;
    for (index, sbox) in SBOX.iter().enumerate() {
        let six = ((expanded >> (42 - 6 * index)) & 0x3f) as usize;
        let row = ((six >> 4) & 0x2) | (six & 0x1);
        let column = (six >> 1) & 0x0f;
        substituted = (substituted << 4) | u32::from(sbox[row * 16 + column]);
    }
    permute(u64::from(substituted), &P, 32) as u32
}

fn des_decrypt(key: [u8; 8], block: [u8; 8]) -> [u8; 8] {
    let subkeys = des_subkeys(u64::from_be_bytes(key));
    let permuted = permute(u64::from_be_bytes(block), &IP, 64);
    let mut left = (permuted >> 32) as u32;
    let mut right = permuted as u32;
    for subkey in subkeys.iter().rev() {
        let next_left = right;
        right = left ^ des_round(right, *subkey);
        left = next_left;
    }
    let preoutput = (u64::from(right) << 32) | u64::from(left);
    permute(preoutput, &FP, 64).to_be_bytes()
}

fn transform_key(key: &[u8; 7]) -> [u8; 8] {
    [
        key[0] >> 1,
        ((key[0] & 0x01) << 6) | (key[1] >> 2),
        ((key[1] & 0x03) << 5) | (key[2] >> 3),
        ((key[2] & 0x07) << 4) | (key[3] >> 4),
        ((key[3] & 0x0f) << 3) | (key[4] >> 5),
        ((key[4] & 0x1f) << 2) | (key[5] >> 6),
        ((key[5] & 0x3f) << 1) | (key[6] >> 7),
        key[6] & 0x7f,
    ]
}

fn rid_des_keys(rid: u32) -> ([u8; 8], [u8; 8]) {
    let rid = rid.to_le_bytes();
    let key1 = [rid[0], rid[1], rid[2], rid[3], rid[0], rid[1], rid[2]];
    let key2 = [rid[3], rid[0], rid[1], rid[2], rid[3], rid[0], rid[1]];
    (transform_key(&key1), transform_key(&key2))
}

fn aes128_expand(key: &[u8; 16]) -> [[u8; 16]; 11] {
    const RCON: [u8; 11] = [0, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54];
    let mut words = [[0u8; 4]; 44];
    for (index, word) in words.iter_mut().take(4).enumerate() {
        word.copy_from_slice(&key[index * 4..index * 4 + 4]);
    }
    for index in 4..44 {
        let mut temp = words[index - 1];
        if index % 4 == 0 {
            temp = [temp[1], temp[2], temp[3], temp[0]];
            for byte in &mut temp {
                *byte = AES_SBOX[*byte as usize];
            }
            temp[0] ^= RCON[index / 4];
        }
        for byte in 0..4 {
            words[index][byte] = words[index - 4][byte] ^ temp[byte];
        }
    }
    let mut round_keys = [[0u8; 16]; 11];
    for round in 0..11 {
        for column in 0..4 {
            round_keys[round][column * 4..column * 4 + 4]
                .copy_from_slice(&words[round * 4 + column]);
        }
    }
    round_keys
}

fn aes_add_round_key(state: &mut [u8; 16], key: &[u8; 16]) {
    for (byte, key) in state.iter_mut().zip(key.iter()) {
        *byte ^= key;
    }
}

fn aes_inv_shift_rows(state: &mut [u8; 16]) {
    for row in 1..4 {
        let row_values = [state[row], state[4 + row], state[8 + row], state[12 + row]];
        for column in 0..4 {
            state[column * 4 + row] = row_values[(column + 4 - row) % 4];
        }
    }
}

fn aes_inv_sub_bytes(state: &mut [u8; 16]) {
    for byte in state {
        *byte = AES_INV_SBOX[*byte as usize];
    }
}

fn aes_mul(mut value: u8, mut factor: u8) -> u8 {
    let mut result = 0u8;
    while factor != 0 {
        if factor & 1 != 0 {
            result ^= value;
        }
        let high = value & 0x80;
        value <<= 1;
        if high != 0 {
            value ^= 0x1b;
        }
        factor >>= 1;
    }
    result
}

fn aes_inv_mix_columns(state: &mut [u8; 16]) {
    for column in 0..4 {
        let values = [
            state[column * 4],
            state[column * 4 + 1],
            state[column * 4 + 2],
            state[column * 4 + 3],
        ];
        state[column * 4] = aes_mul(values[0], 14)
            ^ aes_mul(values[1], 11)
            ^ aes_mul(values[2], 13)
            ^ aes_mul(values[3], 9);
        state[column * 4 + 1] = aes_mul(values[0], 9)
            ^ aes_mul(values[1], 14)
            ^ aes_mul(values[2], 11)
            ^ aes_mul(values[3], 13);
        state[column * 4 + 2] = aes_mul(values[0], 13)
            ^ aes_mul(values[1], 9)
            ^ aes_mul(values[2], 14)
            ^ aes_mul(values[3], 11);
        state[column * 4 + 3] = aes_mul(values[0], 11)
            ^ aes_mul(values[1], 13)
            ^ aes_mul(values[2], 9)
            ^ aes_mul(values[3], 14);
    }
}

fn aes128_decrypt_block(round_keys: &[[u8; 16]; 11], block: [u8; 16]) -> [u8; 16] {
    let mut state = block;
    aes_add_round_key(&mut state, &round_keys[10]);
    for round in (1..10).rev() {
        aes_inv_shift_rows(&mut state);
        aes_inv_sub_bytes(&mut state);
        aes_add_round_key(&mut state, &round_keys[round]);
        aes_inv_mix_columns(&mut state);
    }
    aes_inv_shift_rows(&mut state);
    aes_inv_sub_bytes(&mut state);
    aes_add_round_key(&mut state, &round_keys[0]);
    state
}

fn aes128_cbc_decrypt(key: &[u8; 16], iv: &[u8; 16], data: &[u8]) -> Result<Vec<u8>, ExtractError> {
    if data.is_empty() || data.len() % 16 != 0 {
        return Err(invalid("AES ciphertext is not a whole number of blocks"));
    }
    let round_keys = aes128_expand(key);
    let mut previous = *iv;
    let mut output = Vec::with_capacity(data.len());
    for chunk in data.chunks_exact(16) {
        let mut block = [0u8; 16];
        block.copy_from_slice(chunk);
        let decrypted = aes128_decrypt_block(&round_keys, block);
        output.extend(
            decrypted
                .iter()
                .zip(previous.iter())
                .map(|(byte, previous)| byte ^ previous),
        );
        previous.copy_from_slice(chunk);
    }
    Ok(output)
}

fn boot_key(classes: &[String]) -> Result<[u8; 16], ExtractError> {
    let mut hex = String::new();
    for class in classes {
        hex.push_str(class.trim());
    }
    let scrambled =
        hex::decode(&hex).map_err(|_| invalid("SAM boot key class name is not hexadecimal"))?;
    if scrambled.len() < 16 {
        return Err(invalid("SAM boot key class names are too short"));
    }
    const PERMUTATION: [usize; 16] = [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7];
    let mut key = [0u8; 16];
    for (index, source) in PERMUTATION.iter().enumerate() {
        key[index] = scrambled[*source];
    }
    Ok(key)
}

fn hashed_boot_key(f: &[u8], boot_key: &[u8; 16]) -> Result<[u8; 16], ExtractError> {
    if f.len() < 0xa0 {
        return Err(invalid("SAM account F value is too short"));
    }
    let key0 = &f[0x68..];
    let revision = u32_at(key0, 0)?;
    match revision {
        1 => {
            let salt = &key0[8..24];
            let key = &key0[24..40];
            let checksum = &key0[40..56];
            let rc4_key = md5(&[salt, QWERTY, boot_key, DIGITS])?;
            let mut encrypted = key.to_vec();
            encrypted.extend_from_slice(checksum);
            let decrypted = rc4(&rc4_key, &encrypted);
            let check = md5(&[&decrypted[..16], DIGITS, &decrypted[..16], QWERTY])?;
            if check != decrypted[16..32] {
                return Err(invalid("SAM hashed boot key checksum mismatch"));
            }
            let mut key = [0u8; 16];
            key.copy_from_slice(&decrypted[..16]);
            Ok(key)
        }
        2 | 3 => {
            let salt = &key0[16..32];
            let data_length = u32_at(key0, 12)? as usize;
            let data = key0
                .get(32..32 + data_length)
                .ok_or_else(|| invalid("truncated SAM AES key data"))?;
            let decrypted = aes128_cbc_decrypt(boot_key, salt.try_into().unwrap(), data)?;
            if decrypted.len() < 16 {
                return Err(invalid("SAM AES key data is too short"));
            }
            let mut key = [0u8; 16];
            key.copy_from_slice(&decrypted[..16]);
            Ok(key)
        }
        _ => Err(invalid("unknown SAM account key revision")),
    }
}

fn decrypt_old_hash(
    rid: u32,
    encrypted: &[u8],
    hashed_boot_key: &[u8; 16],
) -> Result<[u8; 16], ExtractError> {
    if encrypted.len() < 16 {
        return Err(invalid("truncated SAM hash value"));
    }
    let (key1, key2) = rid_des_keys(rid);
    let rc4_key = md5(&[hashed_boot_key, &rid.to_le_bytes(), NTPASSWORD])?;
    let intermediate = rc4(&rc4_key, &encrypted[..16]);
    let mut block1 = [0u8; 8];
    block1.copy_from_slice(&intermediate[..8]);
    let mut block2 = [0u8; 8];
    block2.copy_from_slice(&intermediate[8..16]);
    let mut hash = [0u8; 16];
    hash[..8].copy_from_slice(&des_decrypt(key1, block1));
    hash[8..].copy_from_slice(&des_decrypt(key2, block2));
    Ok(hash)
}

fn decrypt_new_hash(
    encrypted: &[u8],
    hashed_boot_key: &[u8; 16],
) -> Result<[u8; 16], ExtractError> {
    if encrypted.len() < 24 + 16 {
        return Err(invalid("truncated SAM AES hash value"));
    }
    let salt: [u8; 16] = encrypted[8..24].try_into().unwrap();
    let ciphertext = &encrypted[24..];
    let decrypted = aes128_cbc_decrypt(hashed_boot_key, &salt, ciphertext)?;
    if decrypted.len() < 16 {
        return Err(invalid("SAM AES hash value is too short"));
    }
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&decrypted[..16]);
    Ok(hash)
}

fn user_hash(
    v: &[u8],
    rid: u32,
    hashed_boot_key: &[u8; 16],
) -> Result<Option<[u8; 16]>, ExtractError> {
    if v.len() < NT_HASH_LENGTH + 4 {
        return Err(invalid("SAM user V value is too short"));
    }
    let offset = u32_at(v, NT_HASH_OFFSET)? as usize;
    let length = u32_at(v, NT_HASH_LENGTH)? as usize;
    if length == 0 {
        return Ok(None);
    }
    if offset < USER_DATA_START || offset + length > v.len() {
        return Err(invalid("SAM user V hash offset is outside the record"));
    }
    let encrypted = &v[offset..offset + length];
    let revision = u16_at(encrypted, 2)?;
    let hash = match revision {
        1 => {
            let hash = encrypted
                .get(4..20)
                .ok_or_else(|| invalid("truncated SAM hash value"))?;
            decrypt_old_hash(rid, hash, hashed_boot_key)?
        }
        2 | 3 => decrypt_new_hash(encrypted, hashed_boot_key)?,
        _ => return Err(invalid("unknown SAM hash revision")),
    };
    Ok(Some(hash))
}

fn value<'a>(values: &'a [Value], name: &str) -> Option<&'a [u8]> {
    values
        .iter()
        .find(|value| value.name.eq_ignore_ascii_case(name))
        .map(|value| value.data.as_slice())
}

fn parse_rid(name: &str) -> Option<u32> {
    if name.len() == 8 && name.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        u32::from_str_radix(name, 16).ok()
    } else {
        None
    }
}

fn account_boot_key(hive: &Hive<'_>, account: &Key) -> Result<[u8; 16], ExtractError> {
    let mut classes = Vec::with_capacity(4);
    for name in ["JD", "Skew1", "GBG", "Data"] {
        let key = hive
            .find_child(account, name)?
            .ok_or_else(|| unsupported(format!("SAM hive has no {name} class key")))?;
        classes.push(hive.class_name(&key)?);
    }
    boot_key(&classes)
}

fn system_boot_key(artifact: &Artifact) -> Option<Result<[u8; 16], ExtractError>> {
    let source = artifact.member("SYSTEM")?;
    let data = source.read_all().ok()?;
    let hive = Hive::parse(&data).ok()?;
    let root = hive.key(hive.root).ok()?;
    let select = hive.find_child(&root, "Select").ok()??;
    let values = hive.values(&select).ok()?;
    let current = value(&values, "Current")
        .and_then(|data| data.get(..4))
        .map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))?;
    let control_set = format!("ControlSet{current:03}");
    let lsa = hive
        .find_path(root, &[control_set.as_str(), "Control", "Lsa"])
        .ok()??;
    Some(account_boot_key(&hive, &lsa))
}

fn roam_key<'a>(hive: &'a Hive<'a>, root: Key) -> Result<Option<Key>, ExtractError> {
    if root.name.eq_ignore_ascii_case("SAM") {
        return Ok(Some(root));
    }
    hive.find_child(&root, "SAM")
}

fn sam_hashes(artifact: &Artifact, data: &[u8]) -> Result<Vec<Ntlm>, ExtractError> {
    let hive = Hive::parse(data)?;
    let root = hive.key(hive.root)?;
    let sam = roam_key(&hive, root)?.ok_or_else(|| unsupported("registry hive has no SAM key"))?;
    let account = hive
        .find_path(sam, &["Domains", "Account"])?
        .ok_or_else(|| unsupported("SAM hive has no Domains\\Account key"))?;
    let users = hive
        .find_child(&account, "Users")?
        .ok_or_else(|| unsupported("SAM account has no Users key"))?;

    let boot_key = match account_boot_key(&hive, &account) {
        Ok(key) => key,
        Err(error) => match system_boot_key(artifact) {
            Some(key) => key?,
            None => return Err(error),
        },
    };
    let account_values = hive.values(&account)?;
    let f = value(&account_values, "F").ok_or_else(|| invalid("SAM account has no F value"))?;
    let hashed_boot_key = hashed_boot_key(f, &boot_key)?;

    let mut hashes = Vec::new();
    for offset in hive.subkeys(&users)? {
        let user = hive.key(offset)?;
        let Some(rid) = parse_rid(&user.name) else {
            continue;
        };
        let values = hive.values(&user)?;
        let v = value(&values, "V")
            .ok_or_else(|| invalid(format!("SAM user {} has no V value", user.name)))?;
        if let Some(digest) = user_hash(v, rid, &hashed_boot_key)? {
            hashes.push(Ntlm { digest });
        }
    }
    if hashes.is_empty() {
        return Err(unsupported("SAM hive contains no NTLM hashes"));
    }
    Ok(hashes)
}

fn data(artifact: &Artifact) -> Result<Vec<u8>, ExtractError> {
    artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })
}

/// Extractor for NTLM hashes in SAM hives and plain hash lists.
pub struct NtlmExtractor;

const COMPANIONS: &[CompanionSpec] = &[CompanionSpec::required(
    "SYSTEM",
    "SYSTEM hive that accompanies the SAM hive",
)];

impl Extractor for NtlmExtractor {
    fn companions(&self) -> &'static [CompanionSpec] {
        COMPANIONS
    }

    fn slug(&self) -> &'static str {
        Ntlm::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        let Ok(data) = data(artifact) else {
            return Probe::No;
        };
        if data.starts_with(REGF) {
            return match sam_hashes(artifact, &data) {
                Ok(_) => Probe::yes("SAM hive user records"),
                Err(_) => Probe::No,
            };
        }
        probe_data::<Ntlm>(&data)
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let data = data(artifact)?;
        let hashes = if data.starts_with(REGF) {
            sam_hashes(artifact, &data)?
        } else {
            extract_from_data::<Ntlm>(&data)?
        };
        Ok(hashes
            .into_iter()
            .map(|hash| Box::new(hash) as Box<dyn HashValue>)
            .collect())
    }
}

const AES_SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const AES_INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn des_decrypts_the_standard_vector() {
        let key = [0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1];
        let block = [0x85, 0xe8, 0x13, 0x54, 0x0f, 0x0a, 0xb4, 0x05];
        assert_eq!(
            des_decrypt(key, block),
            [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]
        );
    }

    #[test]
    fn aes128_cbc_decrypts_a_known_vector() {
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let iv = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let ciphertext = [
            0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9,
            0x19, 0x7d, 0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a,
            0x91, 0x76, 0x78, 0xb2,
        ];
        let plaintext = aes128_cbc_decrypt(&key, &iv, &ciphertext).unwrap();
        assert_eq!(
            &plaintext[..16],
            [
                0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
                0x17, 0x2a,
            ]
        );
    }

    #[test]
    fn rc4_matches_a_known_vector() {
        let output = rc4(b"Key", b"Plaintext");
        assert_eq!(hex::encode(output), "bbf316e8d940af0ad3");
    }
}
