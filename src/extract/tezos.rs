//! Tezos wallet extraction.

use std::str;

use serde_json::{Map, Value};

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Tezos;
use crate::{HashType, HashValue};

pub struct TezosExtractor;

const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const ITERATIONS: u32 = 2048;
const MAX_DEPTH: usize = 16;

const K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut state: [u32; 8] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];
    let mut message = data.to_vec();
    let bit_length = (data.len() as u64).wrapping_mul(8);
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_length.to_be_bytes());

    for chunk in message.chunks_exact(64) {
        let mut words = [0u32; 64];
        for (index, word) in words.iter_mut().take(16).enumerate() {
            let start = index * 4;
            *word = u32::from_be_bytes([
                chunk[start],
                chunk[start + 1],
                chunk[start + 2],
                chunk[start + 3],
            ]);
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for index in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choose = (e & f) ^ (!e & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(choose)
                .wrapping_add(K[index])
                .wrapping_add(words[index]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        for (slot, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *slot = slot.wrapping_add(value);
        }
    }

    let mut digest = [0u8; 32];
    for (index, word) in state.iter().enumerate() {
        digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    digest
}

fn base58_decode(input: &str) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    for character in input.bytes() {
        let digit = ALPHABET
            .iter()
            .position(|candidate| *candidate == character)?;
        let mut carry = digit as u32;
        for byte in &mut bytes {
            let value = u32::from(*byte) * 58 + carry;
            *byte = (value & 0xff) as u8;
            carry = value >> 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let zeros = input.bytes().take_while(|byte| *byte == b'1').count();
    let mut decoded = vec![0u8; zeros];
    decoded.extend(bytes.iter().rev());
    Some(decoded)
}

fn raw_address(address: &str) -> Option<String> {
    let data = base58_decode(address)?;
    if data.len() != 27 || data[0] != 6 || data[1] != 0xa1 || data[2] != 0x9f {
        return None;
    }
    let checksum = sha256(&sha256(&data[..23]));
    if checksum[..4] != data[23..27] {
        return None;
    }
    Some(crate::format::hex(&data[1..23]))
}

fn mnemonic(value: &Value) -> Option<String> {
    match value {
        Value::String(text) if !text.trim().is_empty() => Some(text.trim().to_owned()),
        Value::Array(words) => {
            let words: Option<Vec<&str>> = words
                .iter()
                .map(Value::as_str)
                .map(|word| word.map(str::trim))
                .collect();
            let words = words?;
            if words.is_empty() || words.iter().any(|word| word.is_empty()) {
                return None;
            }
            Some(words.join(" "))
        }
        _ => None,
    }
}

fn object(map: &Map<String, Value>) -> Result<Option<Tezos>, ExtractError> {
    let Some(value) = map.get("mnemonic") else {
        return Ok(None);
    };
    let mnemonic = mnemonic(value)
        .ok_or_else(|| ExtractError::Invalid("invalid Tezos mnemonic".to_owned()))?;
    let email = map
        .get("email")
        .and_then(Value::as_str)
        .filter(|email| !email.is_empty())
        .ok_or_else(|| ExtractError::Invalid("missing Tezos email".to_owned()))?;
    let address = map
        .get("pkh")
        .or_else(|| map.get("address"))
        .and_then(Value::as_str)
        .ok_or_else(|| ExtractError::Invalid("missing Tezos address".to_owned()))?;
    if !address.starts_with("tz1") {
        return Err(ExtractError::Unsupported(
            "unsupported Tezos address type".to_owned(),
        ));
    }
    let raw = raw_address(address)
        .ok_or_else(|| ExtractError::Invalid("invalid Tezos address checksum".to_owned()))?;
    Ok(Some(Tezos {
        fields: format!("1*{ITERATIONS}*{mnemonic}*{email}*{address}*{raw}"),
    }))
}

fn collect(value: &Value, depth: usize, hashes: &mut Vec<Tezos>) -> Result<(), ExtractError> {
    if depth > MAX_DEPTH {
        return Err(ExtractError::Invalid(
            "Tezos wallet nesting is too deep".to_owned(),
        ));
    }
    match value {
        Value::Object(map) => {
            if let Some(hash) = object(map)? {
                hashes.push(hash);
            }
            for value in map.values() {
                collect(value, depth + 1, hashes)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                collect(value, depth + 1, hashes)?;
            }
        }
        Value::String(text) if text.starts_with('{') || text.starts_with('[') => {
            let nested: Value = serde_json::from_str(text).map_err(|error| {
                ExtractError::Invalid(format!("invalid nested Tezos JSON: {error}"))
            })?;
            collect(&nested, depth + 1, hashes)?;
        }
        _ => {}
    }
    Ok(())
}

fn parse(artifact: &Artifact) -> Result<Vec<Tezos>, ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    let text = str::from_utf8(&data)
        .map_err(|_| ExtractError::Invalid("Tezos wallet is not UTF-8".to_owned()))?;
    let document: Value = serde_json::from_str(text)
        .map_err(|error| ExtractError::Invalid(format!("invalid Tezos wallet JSON: {error}")))?;
    let mut hashes = Vec::new();
    collect(&document, 0, &mut hashes)?;
    if hashes.is_empty() {
        return Err(ExtractError::Unsupported(
            "no Tezos wallet found".to_owned(),
        ));
    }
    Ok(hashes)
}

impl Extractor for TezosExtractor {
    fn slug(&self) -> &'static str {
        Tezos::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse(artifact) {
            Ok(_) => Probe::yes("Tezos wallet JSON"),
            Err(_) => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(parse(artifact)?
            .into_iter()
            .map(|hash| Box::new(hash) as Box<dyn HashValue>)
            .collect())
    }
}
