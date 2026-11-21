//! FileVault 2 CoreStorage volume extraction.

use std::io;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use byteorder::{ByteOrder, LittleEndian};
use roxmltree::Document;

use omniex::extract::{Artifact, ExtractError, Extracted, Extractor, Probe, ReadAt};
use omniex::types::FileVault2;
use omniex::{HashType, HashValue};

pub struct FileVault2Extractor;

const HEADER_SIZE: usize = 512;
const CHUNK_SIZE: usize = 1 << 20;
const ENCRYPTED_UNIT: usize = 8192;
const USER_TYPES: [u32; 2] = [0x1006_0002, 0x1000_0001];

fn gf_mul(mut left: u8, mut right: u8) -> u8 {
    let mut product = 0;
    for _ in 0..8 {
        if right & 1 != 0 {
            product ^= left;
        }
        let high = left & 0x80;
        left <<= 1;
        if high != 0 {
            left ^= 0x1b;
        }
        right >>= 1;
    }
    product
}

fn gf_inverse(value: u8) -> u8 {
    if value == 0 {
        return 0;
    }
    let mut result = 1;
    let mut base = value;
    let mut exponent = 254u16;
    while exponent > 0 {
        if exponent & 1 != 0 {
            result = gf_mul(result, base);
        }
        base = gf_mul(base, base);
        exponent >>= 1;
    }
    result
}

fn sbox() -> [u8; 256] {
    let mut table = [0; 256];
    for (value, slot) in table.iter_mut().enumerate() {
        let inverse = gf_inverse(value as u8);
        *slot = inverse
            ^ inverse.rotate_left(1)
            ^ inverse.rotate_left(2)
            ^ inverse.rotate_left(3)
            ^ inverse.rotate_left(4)
            ^ 0x63;
    }
    table
}

fn inverse_sbox(forward: &[u8; 256]) -> [u8; 256] {
    let mut table = [0; 256];
    for (value, substituted) in forward.iter().enumerate() {
        table[*substituted as usize] = value as u8;
    }
    table
}

struct Aes {
    keys: Vec<[u8; 16]>,
    rounds: usize,
    forward: [u8; 256],
    inverse: [u8; 256],
}

impl Aes {
    fn new(key: &[u8]) -> Option<Self> {
        if !matches!(key.len(), 16 | 32) {
            return None;
        }
        let words = key.len() / 4;
        let rounds = words + 6;
        let total = 4 * (rounds + 1);
        let forward = sbox();
        let mut schedule = vec![[0u8; 4]; total];
        for (index, word) in schedule.iter_mut().take(words).enumerate() {
            word.copy_from_slice(&key[index * 4..index * 4 + 4]);
        }
        let mut rcon = 1u8;
        for index in words..total {
            let mut temp = schedule[index - 1];
            if index % words == 0 {
                temp.rotate_left(1);
                for byte in &mut temp {
                    *byte = forward[*byte as usize];
                }
                temp[0] ^= rcon;
                rcon = gf_mul(rcon, 2);
            } else if words > 6 && index % words == 4 {
                for byte in &mut temp {
                    *byte = forward[*byte as usize];
                }
            }
            for position in 0..4 {
                schedule[index][position] = schedule[index - words][position] ^ temp[position];
            }
        }
        let mut keys = Vec::with_capacity(rounds + 1);
        for round in 0..=rounds {
            let mut block = [0u8; 16];
            for column in 0..4 {
                block[column * 4..column * 4 + 4].copy_from_slice(&schedule[round * 4 + column]);
            }
            keys.push(block);
        }
        Some(Self {
            keys,
            rounds,
            inverse: inverse_sbox(&forward),
            forward,
        })
    }

    fn add_round_key(&self, block: &mut [u8; 16], round: usize) {
        for (byte, key) in block.iter_mut().zip(&self.keys[round]) {
            *byte ^= key;
        }
    }

    fn shift_rows(block: &mut [u8; 16]) {
        let original = *block;
        for row in 1..4 {
            for column in 0..4 {
                block[row + 4 * column] = original[row + 4 * ((column + row) % 4)];
            }
        }
    }

    fn inverse_shift_rows(block: &mut [u8; 16]) {
        let original = *block;
        for row in 1..4 {
            for column in 0..4 {
                block[row + 4 * column] = original[row + 4 * ((column + 4 - row) % 4)];
            }
        }
    }

    fn mix_columns(block: &mut [u8; 16]) {
        for column in 0..4 {
            let start = column * 4;
            let a = [
                block[start],
                block[start + 1],
                block[start + 2],
                block[start + 3],
            ];
            block[start] = gf_mul(a[0], 2) ^ gf_mul(a[1], 3) ^ a[2] ^ a[3];
            block[start + 1] = a[0] ^ gf_mul(a[1], 2) ^ gf_mul(a[2], 3) ^ a[3];
            block[start + 2] = a[0] ^ a[1] ^ gf_mul(a[2], 2) ^ gf_mul(a[3], 3);
            block[start + 3] = gf_mul(a[0], 3) ^ a[1] ^ a[2] ^ gf_mul(a[3], 2);
        }
    }

    fn inverse_mix_columns(block: &mut [u8; 16]) {
        for column in 0..4 {
            let start = column * 4;
            let a = [
                block[start],
                block[start + 1],
                block[start + 2],
                block[start + 3],
            ];
            block[start] = gf_mul(a[0], 14) ^ gf_mul(a[1], 11) ^ gf_mul(a[2], 13) ^ gf_mul(a[3], 9);
            block[start + 1] =
                gf_mul(a[0], 9) ^ gf_mul(a[1], 14) ^ gf_mul(a[2], 11) ^ gf_mul(a[3], 13);
            block[start + 2] =
                gf_mul(a[0], 13) ^ gf_mul(a[1], 9) ^ gf_mul(a[2], 14) ^ gf_mul(a[3], 11);
            block[start + 3] =
                gf_mul(a[0], 11) ^ gf_mul(a[1], 13) ^ gf_mul(a[2], 9) ^ gf_mul(a[3], 14);
        }
    }

    fn encrypt_block(&self, block: &mut [u8; 16]) {
        self.add_round_key(block, 0);
        for round in 1..self.rounds {
            for byte in block.iter_mut() {
                *byte = self.forward[*byte as usize];
            }
            Self::shift_rows(block);
            Self::mix_columns(block);
            self.add_round_key(block, round);
        }
        for byte in block.iter_mut() {
            *byte = self.forward[*byte as usize];
        }
        Self::shift_rows(block);
        self.add_round_key(block, self.rounds);
    }

    fn decrypt_block(&self, block: &mut [u8; 16]) {
        self.add_round_key(block, self.rounds);
        for round in (1..self.rounds).rev() {
            Self::inverse_shift_rows(block);
            for byte in block.iter_mut() {
                *byte = self.inverse[*byte as usize];
            }
            self.add_round_key(block, round);
            Self::inverse_mix_columns(block);
        }
        Self::inverse_shift_rows(block);
        for byte in block.iter_mut() {
            *byte = self.inverse[*byte as usize];
        }
        self.add_round_key(block, 0);
    }
}

fn xts_blocks(key: &[u8], tweak: [u8; 16], data: &mut [u8]) -> Result<(), ExtractError> {
    let half = key.len() / 2;
    let data_cipher = Aes::new(&key[..half])
        .ok_or_else(|| ExtractError::Invalid("invalid AES data key length".to_owned()))?;
    let tweak_cipher = Aes::new(&key[half..])
        .ok_or_else(|| ExtractError::Invalid("invalid AES tweak key length".to_owned()))?;
    let mut current = tweak;
    tweak_cipher.encrypt_block(&mut current);
    for chunk in data.chunks_mut(16) {
        let mut block: [u8; 16] = chunk
            .try_into()
            .map_err(|_| ExtractError::Invalid("XTS unit is not block aligned".to_owned()))?;
        for (byte, mask) in block.iter_mut().zip(current) {
            *byte ^= mask;
        }
        data_cipher.decrypt_block(&mut block);
        for (byte, mask) in block.iter_mut().zip(current) {
            *byte ^= mask;
        }
        chunk.copy_from_slice(&block);
        let mut carry = 0u8;
        for byte in &mut current {
            let next = *byte >> 7;
            *byte = (*byte << 1) | carry;
            carry = next;
        }
        if carry != 0 {
            current[0] ^= 0x87;
        }
    }
    Ok(())
}

pub(super) fn xts_decrypt(key: &[u8], tweak: u128, data: &mut [u8]) -> Result<(), ExtractError> {
    if !matches!(key.len(), 32 | 64) {
        return Err(ExtractError::Unsupported(
            "unsupported AES-XTS key length".to_owned(),
        ));
    }
    if !data.len().is_multiple_of(16) {
        return Err(ExtractError::Invalid(
            "AES-XTS data is not block aligned".to_owned(),
        ));
    }
    xts_blocks(key, tweak.to_le_bytes(), data)
}

pub(super) fn xts_decrypt_sectors(
    key: &[u8],
    first_sector: u64,
    data: &mut [u8],
    sector_size: usize,
) -> Result<(), ExtractError> {
    if sector_size == 0 || !sector_size.is_multiple_of(16) {
        return Err(ExtractError::Invalid("invalid XTS sector size".to_owned()));
    }
    for (index, sector) in data.chunks_mut(sector_size).enumerate() {
        let tweak = u128::from(first_sector) + index as u128;
        xts_blocks(key, tweak.to_le_bytes(), sector)?;
    }
    Ok(())
}

pub(super) fn read_exact(
    source: &dyn ReadAt,
    offset: u64,
    len: usize,
    what: &str,
) -> Result<Vec<u8>, ExtractError> {
    let mut data = vec![0; len];
    source
        .read_exact_at(offset, &mut data)
        .map_err(|error| ExtractError::Invalid(format!("cannot read {what}: {error}")))?;
    Ok(data)
}

fn candidates(source: &dyn ReadAt) -> io::Result<Vec<u64>> {
    let mut offsets = Vec::new();
    let mut chunk = vec![0u8; CHUNK_SIZE];
    let mut base = 0u64;
    while base < source.len() {
        let read = source.read_at(base, &mut chunk)?;
        if read < 2 {
            break;
        }
        for index in 0..read - 1 {
            if chunk[index] != b'C' || chunk[index + 1] != b'S' {
                continue;
            }
            let signature = base + index as u64;
            if signature < 88 || !(signature - 88).is_multiple_of(HEADER_SIZE as u64) {
                continue;
            }
            offsets.push(signature - 88);
        }
        base += read as u64;
    }
    Ok(offsets)
}

fn integer(data: &[u8], offset: usize, len: usize) -> Result<u64, ExtractError> {
    let bytes = data
        .get(offset..offset + len)
        .ok_or_else(|| ExtractError::Invalid("truncated CoreStorage header".to_owned()))?;
    let mut value = 0u64;
    for (shift, byte) in bytes.iter().enumerate() {
        value |= u64::from(*byte) << (8 * shift);
    }
    Ok(value)
}

fn is_power_of_two(value: u64) -> bool {
    value != 0 && value.is_power_of_two()
}

fn parse_user(xml: &str) -> Result<Vec<FileVault2>, ExtractError> {
    let xml = xml.find("<plist").map_or(xml, |offset| &xml[offset..]);
    let document = Document::parse(xml)
        .map_err(|error| ExtractError::Invalid(format!("invalid CoreStorage plist: {error}")))?;
    let users = document
        .descendants()
        .find(|node| {
            node.is_element() && node.has_tag_name("key") && node.text() == Some("CryptoUsers")
        })
        .and_then(|node| node.next_sibling_element())
        .filter(|node| node.has_tag_name("array"))
        .ok_or_else(|| ExtractError::Unsupported("missing CoreStorage CryptoUsers".to_owned()))?;

    let mut hashes = Vec::new();
    for user in users.children().filter(|node| node.has_tag_name("dict")) {
        let mut user_type = None;
        let mut wrapped = None;
        for child in user.children().filter(|node| node.is_element()) {
            if !child.has_tag_name("key") {
                continue;
            }
            let Some(value) = child.next_sibling_element() else {
                continue;
            };
            match child.text() {
                Some("UserType") => {
                    user_type = value.text().and_then(parse_integer);
                }
                Some("PassphraseWrappedKEKStruct") => {
                    wrapped = value.text().and_then(|text| {
                        let encoded = text.split_whitespace().collect::<String>();
                        STANDARD.decode(encoded).ok()
                    });
                }
                _ => {}
            }
        }
        let Some(user_type) = user_type else {
            continue;
        };
        if !USER_TYPES.contains(&user_type) {
            continue;
        }
        let Some(wrapped) = wrapped else {
            continue;
        };
        if wrapped.len() < 172 {
            return Err(ExtractError::Invalid(
                "truncated CoreStorage wrapped KEK".to_owned(),
            ));
        }
        let salt: [u8; 16] = wrapped[8..24]
            .try_into()
            .map_err(|_| ExtractError::Invalid("invalid CoreStorage salt".to_owned()))?;
        let wrapped_key: [u8; 24] = wrapped[32..56]
            .try_into()
            .map_err(|_| ExtractError::Invalid("invalid CoreStorage wrapped key".to_owned()))?;
        hashes.push(FileVault2 {
            primary_key: 1,
            salt,
            iterations: LittleEndian::read_u32(&wrapped[168..172]),
            wrapped_key,
        });
    }
    Ok(hashes)
}

fn parse_integer(text: &str) -> Option<u32> {
    let text = text.trim();
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).ok()
    } else {
        text.parse().ok()
    }
}

fn volume(source: &dyn ReadAt, offset: u64) -> Result<Vec<FileVault2>, ExtractError> {
    let header = read_exact(source, offset, HEADER_SIZE, "CoreStorage header")?;
    if &header[88..90] != b"CS" {
        return Err(ExtractError::Unsupported(
            "not a CoreStorage physical volume".to_owned(),
        ));
    }
    if LittleEndian::read_u16(&header[8..10]) != 1
        || LittleEndian::read_u16(&header[10..12]) != 0x0010
    {
        return Err(ExtractError::Unsupported(
            "unsupported CoreStorage header version".to_owned(),
        ));
    }
    if LittleEndian::read_u32(&header[48..52]) != 512 {
        return Err(ExtractError::Unsupported(
            "unsupported CoreStorage sector size".to_owned(),
        ));
    }
    let block_size = integer(&header, 96, 4)?;
    if !is_power_of_two(block_size) || !(512..=1 << 20).contains(&block_size) {
        return Err(ExtractError::Unsupported(
            "unsupported CoreStorage block size".to_owned(),
        ));
    }
    let metadata_count = integer(&header, 94, 2)?;
    if !(1..=8).contains(&metadata_count) {
        return Err(ExtractError::Invalid(
            "invalid CoreStorage metadata block count".to_owned(),
        ));
    }
    let key_size = integer(&header, 168, 4)?;
    let method = integer(&header, 172, 4)?;
    if key_size != 16 || method != 2 {
        return Err(ExtractError::Unsupported(
            "unsupported CoreStorage encryption parameters".to_owned(),
        ));
    }
    let metadata_block = integer(&header, 104, 8)?;
    let key: [u8; 16] = header[176..192]
        .try_into()
        .map_err(|_| ExtractError::Invalid("invalid CoreStorage key".to_owned()))?;
    let tweak_key: [u8; 16] = header[304..320]
        .try_into()
        .map_err(|_| ExtractError::Invalid("invalid CoreStorage UUID".to_owned()))?;
    let mut xts_key = [0u8; 32];
    xts_key[..16].copy_from_slice(&key);
    xts_key[16..].copy_from_slice(&tweak_key);

    let metadata_offset = offset
        .checked_add(metadata_block * block_size)
        .ok_or_else(|| ExtractError::Invalid("CoreStorage metadata offset overflow".to_owned()))?;
    let metadata = read_exact(source, metadata_offset, HEADER_SIZE, "CoreStorage metadata")?;
    if LittleEndian::read_u16(&metadata[8..10]) != 1 {
        return Err(ExtractError::Invalid(
            "invalid CoreStorage metadata version".to_owned(),
        ));
    }
    let block_type = LittleEndian::read_u16(&metadata[10..12]);
    if block_type != 0x0011 {
        return Err(ExtractError::Unsupported(
            "missing CoreStorage metadata block type 0x11".to_owned(),
        ));
    }
    let descriptor_relative = integer(&metadata, 64 + 156, 4)?;
    let xml_relative = integer(&metadata, 64 + 160, 4)?;
    let xml_size = integer(&metadata, 64 + 164, 4)?;
    if xml_size == 0 || xml_size > 1 << 20 {
        return Err(ExtractError::Invalid(
            "invalid CoreStorage XML plist size".to_owned(),
        ));
    }
    let descriptor_offset = metadata_offset
        .checked_add(descriptor_relative)
        .ok_or_else(|| ExtractError::Invalid("CoreStorage descriptor overflow".to_owned()))?;
    let descriptor = read_exact(
        source,
        descriptor_offset,
        512,
        "CoreStorage volume group descriptor",
    )?;
    let primary = integer(&descriptor, 32, 6)?;
    let encrypted_blocks = integer(&descriptor, 8, 8)?;
    let xml_offset = metadata_offset
        .checked_add(xml_relative)
        .ok_or_else(|| ExtractError::Invalid("CoreStorage XML offset overflow".to_owned()))?;
    let xml = read_exact(
        source,
        xml_offset,
        usize::try_from(xml_size)
            .map_err(|_| ExtractError::Invalid("CoreStorage XML is too large".to_owned()))?,
        "CoreStorage XML plist",
    )?;
    let xml = String::from_utf8(xml)
        .map_err(|_| ExtractError::Invalid("CoreStorage plist is not UTF-8".to_owned()))?;
    let mut hashes = match parse_user(&xml) {
        Ok(found) => found,
        Err(ExtractError::Unsupported(_)) => Vec::new(),
        Err(error) => return Err(error),
    };

    let total = encrypted_blocks
        .checked_mul(block_size)
        .ok_or_else(|| ExtractError::Invalid("CoreStorage metadata size overflow".to_owned()))?;
    if total == 0 || total > 64 << 20 {
        return Err(ExtractError::Invalid(
            "invalid CoreStorage encrypted metadata size".to_owned(),
        ));
    }
    let encrypted_offset = offset
        .checked_add(primary * block_size)
        .ok_or_else(|| ExtractError::Invalid("CoreStorage metadata offset overflow".to_owned()))?;
    let encrypted = read_exact(
        source,
        encrypted_offset,
        usize::try_from(total)
            .map_err(|_| ExtractError::Invalid("CoreStorage metadata is too large".to_owned()))?,
        "CoreStorage encrypted metadata",
    )?;
    for (index, unit) in encrypted.chunks(ENCRYPTED_UNIT).enumerate() {
        if unit.len() != ENCRYPTED_UNIT {
            return Err(ExtractError::Invalid(
                "truncated CoreStorage encrypted metadata".to_owned(),
            ));
        }
        let mut plain = unit.to_vec();
        xts_decrypt(&xts_key, index as u128, &mut plain)?;
        if LittleEndian::read_u16(&plain[10..12]) != 0x0019 {
            continue;
        }
        let compressed = usize::try_from(integer(&plain, 64 + 40, 4)?)
            .map_err(|_| ExtractError::Invalid("CoreStorage plist is too large".to_owned()))?;
        let uncompressed = usize::try_from(integer(&plain, 64 + 44, 4)?)
            .map_err(|_| ExtractError::Invalid("CoreStorage plist is too large".to_owned()))?;
        if compressed != uncompressed {
            return Err(ExtractError::Unsupported(
                "compressed CoreStorage metadata plist is unsupported".to_owned(),
            ));
        }
        let offset_in_block = usize::try_from(integer(&plain, 64 + 48, 4)?).map_err(|_| {
            ExtractError::Invalid("CoreStorage plist offset is too large".to_owned())
        })?;
        let size = usize::try_from(integer(&plain, 64 + 52, 4)?)
            .map_err(|_| ExtractError::Invalid("CoreStorage plist size is too large".to_owned()))?;
        let xml = plain
            .get(offset_in_block..offset_in_block + size)
            .ok_or_else(|| ExtractError::Invalid("truncated CoreStorage plist".to_owned()))?;
        let xml = std::str::from_utf8(xml)
            .map_err(|_| ExtractError::Invalid("CoreStorage plist is not UTF-8".to_owned()))?;
        hashes.extend(parse_user(xml)?);
    }
    Ok(hashes)
}

fn extract_all(artifact: &Artifact) -> Result<Vec<FileVault2>, ExtractError> {
    let source = artifact.primary();
    let offsets = candidates(source).map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    let mut hashes = Vec::new();
    for offset in offsets {
        match volume(source, offset) {
            Ok(found) => hashes.extend(found),
            Err(ExtractError::Unsupported(_)) => {}
            Err(error) => return Err(error),
        }
    }
    if hashes.is_empty() {
        return Err(ExtractError::Unsupported(
            "no FileVault 2 encryption context found".to_owned(),
        ));
    }
    Ok(hashes)
}

impl Extractor for FileVault2Extractor {
    fn slug(&self) -> &'static str {
        FileVault2::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match volume(artifact.primary(), 0) {
            Ok(_) => Probe::yes("CoreStorage encryption context"),
            Err(_) => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(extract_all(artifact)?
            .into_iter()
            .map(|value| Box::new(value) as Box<dyn HashValue>)
            .collect())
    }
}
