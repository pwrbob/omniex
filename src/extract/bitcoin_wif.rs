//! Raw Bitcoin WIF private key extraction.
//!
//! A WIF key is decoded, its secp256k1 public key is derived, and the matching
//! P2PKH address is emitted as the Bitcoin WIF hash value.

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::BitcoinWif;
use crate::{HashType, HashValue};

pub struct BitcoinWifExtractor;

type U256 = [u64; 4];

const P: U256 = [
    0xffff_fffe_ffff_fc2f,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
];
const P_MINUS_2: U256 = [
    0xffff_fffe_ffff_fc2d,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
];
const GX: U256 = [
    0x59f2_815b_16f8_1798,
    0x029b_fcdb_2dce_28d9,
    0x55a0_6295_ce87_0b07,
    0x79be_667e_f9dc_bbac,
];
const GY: U256 = [
    0x9c47_d08f_fb10_d4b8,
    0xfd17_b448_a685_5419,
    0x5da4_fbfc_0e11_08a8,
    0x483a_da77_26a3_c465,
];
const TWO_256_MOD_P: U256 = [0x0000_0001_0000_03d1, 0, 0, 0];
fn is_zero(value: &U256) -> bool {
    value.iter().all(|limb| *limb == 0)
}

fn ge(a: &U256, b: &U256) -> bool {
    for index in (0..4).rev() {
        if a[index] != b[index] {
            return a[index] > b[index];
        }
    }
    true
}

fn add_raw(a: &U256, b: &U256) -> (U256, bool) {
    let mut result = [0; 4];
    let mut carry = 0u128;
    for index in 0..4 {
        let sum = u128::from(a[index]) + u128::from(b[index]) + carry;
        result[index] = sum as u64;
        carry = sum >> 64;
    }
    (result, carry != 0)
}

fn sub_raw(a: &U256, b: &U256) -> (U256, bool) {
    let mut result = [0; 4];
    let mut borrow = 0i128;
    for index in 0..4 {
        let difference = i128::from(a[index]) - i128::from(b[index]) - borrow;
        if difference < 0 {
            result[index] = (difference + (1i128 << 64)) as u64;
            borrow = 1;
        } else {
            result[index] = difference as u64;
            borrow = 0;
        }
    }
    (result, borrow != 0)
}

fn add_mod(a: &U256, b: &U256) -> U256 {
    let (sum, carry) = add_raw(a, b);
    if carry {
        add_mod(&sum, &TWO_256_MOD_P)
    } else if ge(&sum, &P) {
        sub_raw(&sum, &P).0
    } else {
        sum
    }
}

fn sub_mod(a: &U256, b: &U256) -> U256 {
    let (difference, borrow) = sub_raw(a, b);
    if borrow {
        sub_raw(&difference, &TWO_256_MOD_P).0
    } else {
        difference
    }
}

fn mul_mod(a: &U256, b: &U256) -> U256 {
    let mut result = [0; 4];
    let mut addend = *a;
    for index in 0..256 {
        if (b[index / 64] >> (index % 64)) & 1 == 1 {
            result = add_mod(&result, &addend);
        }
        addend = add_mod(&addend, &addend);
    }
    result
}

fn inv_mod(value: &U256) -> U256 {
    let mut result = [1, 0, 0, 0];
    let mut base = *value;
    for index in 0..256 {
        if (P_MINUS_2[index / 64] >> (index % 64)) & 1 == 1 {
            result = mul_mod(&result, &base);
        }
        base = mul_mod(&base, &base);
    }
    result
}

fn to_be(value: &U256) -> [u8; 32] {
    let mut out = [0; 32];
    for index in 0..4 {
        out[24 - index * 8..32 - index * 8].copy_from_slice(&value[index].to_be_bytes());
    }
    out
}

#[derive(Clone, Copy)]
struct Jacobian {
    x: U256,
    y: U256,
    z: U256,
}

const INFINITY: Jacobian = Jacobian {
    x: [0; 4],
    y: [0; 4],
    z: [0; 4],
};

fn double(point: &Jacobian) -> Jacobian {
    if is_zero(&point.z) || is_zero(&point.y) {
        return INFINITY;
    }
    let a = mul_mod(&point.x, &point.x);
    let b = mul_mod(&point.y, &point.y);
    let c = mul_mod(&b, &b);
    let xb = add_mod(&point.x, &b);
    let d = sub_mod(&sub_mod(&mul_mod(&xb, &xb), &a), &c);
    let d = add_mod(&d, &d);
    let e = add_mod(&add_mod(&a, &a), &a);
    let f = mul_mod(&e, &e);
    let x3 = sub_mod(&f, &add_mod(&d, &d));
    let c8 = {
        let c2 = add_mod(&c, &c);
        let c4 = add_mod(&c2, &c2);
        add_mod(&c4, &c4)
    };
    let y3 = sub_mod(&mul_mod(&e, &sub_mod(&d, &x3)), &c8);
    let z3 = mul_mod(&add_mod(&point.y, &point.y), &point.z);
    Jacobian {
        x: x3,
        y: y3,
        z: z3,
    }
}

fn add(point: &Jacobian, other: &Jacobian) -> Jacobian {
    if is_zero(&point.z) {
        return *other;
    }
    if is_zero(&other.z) {
        return *point;
    }
    let z1z1 = mul_mod(&point.z, &point.z);
    let z2z2 = mul_mod(&other.z, &other.z);
    let u1 = mul_mod(&point.x, &z2z2);
    let u2 = mul_mod(&other.x, &z1z1);
    let z1z1z1 = mul_mod(&z1z1, &point.z);
    let z2z2z2 = mul_mod(&z2z2, &other.z);
    let s1 = mul_mod(&point.y, &z2z2z2);
    let s2 = mul_mod(&other.y, &z1z1z1);
    if u1 == u2 {
        return if s1 == s2 { double(point) } else { INFINITY };
    }
    let h = sub_mod(&u2, &u1);
    let r = sub_mod(&s2, &s1);
    let h2 = mul_mod(&h, &h);
    let h3 = mul_mod(&h2, &h);
    let u1h2 = mul_mod(&u1, &h2);
    let x3 = sub_mod(&sub_mod(&mul_mod(&r, &r), &h3), &add_mod(&u1h2, &u1h2));
    let y3 = sub_mod(&mul_mod(&r, &sub_mod(&u1h2, &x3)), &mul_mod(&s1, &h3));
    let z3 = mul_mod(&mul_mod(&h, &point.z), &other.z);
    Jacobian {
        x: x3,
        y: y3,
        z: z3,
    }
}

fn multiply(point: &Jacobian, scalar: &[u8; 32]) -> Jacobian {
    let mut result = INFINITY;
    for byte in scalar {
        for bit in (0..8).rev() {
            result = double(&result);
            if (byte >> bit) & 1 == 1 {
                result = add(&result, point);
            }
        }
    }
    result
}

fn public_key(private: &[u8; 32], compressed: bool) -> [u8; 65] {
    let generator = Jacobian {
        x: GX,
        y: GY,
        z: [1, 0, 0, 0],
    };
    let point = multiply(&generator, private);
    let zinv = inv_mod(&point.z);
    let zinv2 = mul_mod(&zinv, &zinv);
    let x = mul_mod(&point.x, &zinv2);
    let y = mul_mod(&point.y, &mul_mod(&zinv2, &zinv));
    let x_bytes = to_be(&x);
    let y_bytes = to_be(&y);
    let mut out = [0; 65];
    if compressed {
        out[0] = if y_bytes[31] & 1 == 0 { 0x02 } else { 0x03 };
        out[1..33].copy_from_slice(&x_bytes);
        out[33..].fill(0);
    } else {
        out[0] = 0x04;
        out[1..33].copy_from_slice(&x_bytes);
        out[33..65].copy_from_slice(&y_bytes);
    }
    out
}

fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut state = [
        0x6a09e667u32,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut message = data.to_vec();
    let bit_len = (data.len() as u64) * 8;
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in message.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        for index in 0..16 {
            w[index] = u32::from_be_bytes([
                chunk[index * 4],
                chunk[index * 4 + 1],
                chunk[index * 4 + 2],
                chunk[index * 4 + 3],
            ]);
        }
        for index in 16..64 {
            let s0 = w[index - 15].rotate_right(7)
                ^ w[index - 15].rotate_right(18)
                ^ (w[index - 15] >> 3);
            let s1 = w[index - 2].rotate_right(17)
                ^ w[index - 2].rotate_right(19)
                ^ (w[index - 2] >> 10);
            w[index] = w[index - 16]
                .wrapping_add(s0)
                .wrapping_add(w[index - 7])
                .wrapping_add(s1);
        }
        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];
        for index in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choice = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(choice)
                .wrapping_add(K[index])
                .wrapping_add(w[index]);
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
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }
    let mut digest = [0; 32];
    for (index, word) in state.iter().enumerate() {
        digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    digest
}

fn ripemd160(data: &[u8]) -> [u8; 20] {
    const R: [usize; 80] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9,
        5, 2, 14, 11, 8, 3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8,
        12, 4, 13, 3, 7, 15, 14, 5, 6, 2, 4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
    ];
    const RP: [usize; 80] = [
        5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8,
        12, 4, 9, 1, 2, 15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11,
        15, 0, 5, 12, 2, 13, 9, 7, 10, 14, 12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
    ];
    const S: [u32; 80] = [
        11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12,
        15, 9, 11, 7, 13, 12, 11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14,
        15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12, 9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11,
        8, 5, 6,
    ];
    const SP: [u32; 80] = [
        8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7,
        12, 7, 6, 15, 13, 11, 9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11,
        14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8, 8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13,
        11, 11,
    ];
    fn f(index: usize, x: u32, y: u32, z: u32) -> u32 {
        match index {
            0..=15 => x ^ y ^ z,
            16..=31 => (x & y) | ((!x) & z),
            32..=47 => (x | (!y)) ^ z,
            48..=63 => (x & z) | (y & (!z)),
            _ => x ^ (y | (!z)),
        }
    }
    fn k(index: usize) -> u32 {
        match index {
            0..=15 => 0x0000_0000,
            16..=31 => 0x5a82_7999,
            32..=47 => 0x6ed9_eba1,
            48..=63 => 0x8f1b_bcdc,
            _ => 0xa953_fd4e,
        }
    }
    fn kp(index: usize) -> u32 {
        match index {
            0..=15 => 0x50a2_8be6,
            16..=31 => 0x5c4d_d124,
            32..=47 => 0x6d70_3ef3,
            48..=63 => 0x7a6d_76e9,
            _ => 0x0000_0000,
        }
    }
    fn rol(value: u32, shift: u32) -> u32 {
        value.rotate_left(shift)
    }
    let mut message = data.to_vec();
    let bit_len = (data.len() as u64) * 8;
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_le_bytes());
    let mut h = [
        0x6745_2301u32,
        0xefcd_ab89,
        0x98ba_dcfe,
        0x1032_5476,
        0xc3d2_e1f0,
    ];
    for chunk in message.as_chunks::<64>().0 {
        let mut x = [0u32; 16];
        for index in 0..16 {
            x[index] = u32::from_le_bytes([
                chunk[index * 4],
                chunk[index * 4 + 1],
                chunk[index * 4 + 2],
                chunk[index * 4 + 3],
            ]);
        }
        let (mut al, mut bl, mut cl, mut dl, mut el) = (h[0], h[1], h[2], h[3], h[4]);
        let (mut ar, mut br, mut cr, mut dr, mut er) = (h[0], h[1], h[2], h[3], h[4]);
        for index in 0..80 {
            let t = rol(
                al.wrapping_add(f(index, bl, cl, dl))
                    .wrapping_add(x[R[index]])
                    .wrapping_add(k(index)),
                S[index],
            )
            .wrapping_add(el);
            al = el;
            el = dl;
            dl = rol(cl, 10);
            cl = bl;
            bl = t;
            let tp = rol(
                ar.wrapping_add(f(79 - index, br, cr, dr))
                    .wrapping_add(x[RP[index]])
                    .wrapping_add(kp(index)),
                SP[index],
            )
            .wrapping_add(er);
            ar = er;
            er = dr;
            dr = rol(cr, 10);
            cr = br;
            br = tp;
        }
        let t = h[1].wrapping_add(cl).wrapping_add(dr);
        h[1] = h[2].wrapping_add(dl).wrapping_add(er);
        h[2] = h[3].wrapping_add(el).wrapping_add(ar);
        h[3] = h[4].wrapping_add(al).wrapping_add(br);
        h[4] = h[0].wrapping_add(bl).wrapping_add(cr);
        h[0] = t;
    }
    let mut digest = [0; 20];
    for (index, word) in h.iter().enumerate() {
        digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    digest
}

fn base58_alphabet() -> &'static [u8; 58] {
    b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
}

fn base58_encode(data: &[u8]) -> String {
    let mut digits: Vec<u8> = Vec::new();
    for byte in data {
        let mut carry = u32::from(*byte);
        for digit in digits.iter_mut().rev() {
            let value = u32::from(*digit) * 256 + carry;
            *digit = (value % 58) as u8;
            carry = value / 58;
        }
        while carry > 0 {
            digits.insert(0, (carry % 58) as u8);
            carry /= 58;
        }
    }
    let zeros = data.iter().take_while(|byte| **byte == 0).count();
    let alphabet = base58_alphabet();
    let mut out = String::new();
    for _ in 0..zeros {
        out.push('1');
    }
    for digit in digits {
        out.push(alphabet[digit as usize] as char);
    }
    out
}

fn base58_decode(text: &str) -> Option<Vec<u8>> {
    let alphabet = base58_alphabet();
    let mut bytes: Vec<u8> = Vec::new();
    for character in text.bytes() {
        let value = alphabet.iter().position(|entry| *entry == character)? as u32;
        let mut carry = value;
        for byte in bytes.iter_mut().rev() {
            let sum = u32::from(*byte) * 58 + carry;
            *byte = sum as u8;
            carry = sum >> 8;
        }
        while carry > 0 {
            bytes.insert(0, carry as u8);
            carry >>= 8;
        }
    }
    let zeros = text.bytes().take_while(|byte| *byte == b'1').count();
    let mut out = vec![0; zeros];
    out.extend(bytes);
    Some(out)
}

fn address(private: &[u8; 32], compressed: bool) -> String {
    let key = public_key(private, compressed);
    let length = if compressed { 33 } else { 65 };
    let digest = sha256(&key[..length]);
    let hash = ripemd160(&digest);
    let mut payload = Vec::with_capacity(25);
    payload.push(0);
    payload.extend_from_slice(&hash);
    let checksum = sha256(&sha256(&payload));
    payload.extend_from_slice(&checksum[..4]);
    base58_encode(&payload)
}

fn wif_key(text: &str) -> Option<(String, [u8; 32])> {
    let decoded = base58_decode(text)?;
    if !matches!(decoded.len(), 37 | 38) {
        return None;
    }
    let payload_len = decoded.len() - 4;
    let (payload, checksum) = decoded.split_at(payload_len);
    let expected = sha256(&sha256(payload));
    if checksum != &expected[..4] || payload.first() != Some(&0x80) {
        return None;
    }
    let compressed = match (payload.len(), payload.get(33)) {
        (33, _) => false,
        (34, Some(1)) => true,
        _ => return None,
    };
    let mut private = [0; 32];
    private.copy_from_slice(payload.get(1..33)?);
    Some((address(&private, compressed), private))
}

fn candidates(data: &[u8]) -> Vec<String> {
    let alphabet = base58_alphabet();
    let mut values = Vec::new();
    let mut index = 0;
    while index < data.len() {
        if alphabet.contains(&data[index]) {
            let start = index;
            while index < data.len() && alphabet.contains(&data[index]) {
                index += 1;
            }
            if (51..=53).contains(&(index - start))
                && let Ok(text) = std::str::from_utf8(&data[start..index])
                && wif_key(text).is_some()
                && !values.iter().any(|value| value == text)
            {
                values.push(text.to_owned());
            }
        } else {
            index += 1;
        }
    }
    values
}

fn parse(artifact: &Artifact) -> Result<Vec<BitcoinWif>, ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    if data.is_empty() {
        return Err(ExtractError::Invalid(
            "WIF private key file is empty".to_owned(),
        ));
    }
    let values = candidates(&data);
    if values.is_empty() {
        return Err(ExtractError::Unsupported(
            "no valid WIF private key found".to_owned(),
        ));
    }
    Ok(values
        .into_iter()
        .filter_map(|text| {
            let (address, _) = wif_key(&text)?;
            Some(BitcoinWif { address })
        })
        .collect())
}

impl Extractor for BitcoinWifExtractor {
    fn slug(&self) -> &'static str {
        BitcoinWif::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse(artifact) {
            Ok(values) if !values.is_empty() => Probe::yes("Base58Check WIF private key"),
            _ => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(parse(artifact)?
            .into_iter()
            .map(|value| Box::new(value) as Box<dyn HashValue>)
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_vectors() {
        assert_eq!(
            crate::format::hex(sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            crate::format::hex(ripemd160(b"")),
            "9c1185a5c5e9fc54612808977ee8f548b2258d31"
        );
    }

    #[test]
    fn field_arithmetic_vectors() {
        assert!(is_zero(&sub_mod(&P, &P)));
        assert_eq!(
            crate::format::hex(to_be(&mul_mod(&GX, &GX))),
            "8550e7d238fcf3086ba9adcf0fb52a9de3652194d06cb5bb38d50229b854fc49"
        );
        assert_eq!(
            crate::format::hex(to_be(&inv_mod(&[2, 0, 0, 0]))),
            "7fffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffe18"
        );
    }

    #[test]
    fn private_key_one_public_key() {
        let mut key = [0; 32];
        key[31] = 1;
        let public = public_key(&key, true);
        assert_eq!(
            crate::format::hex(&public[1..33]),
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
        assert_eq!(address(&key, true), "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
        assert_eq!(address(&key, false), "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm");
    }

    #[test]
    fn private_key_two_public_key() {
        let mut key = [0; 32];
        key[31] = 2;
        let public = public_key(&key, true);
        assert_eq!(
            crate::format::hex(&public[1..33]),
            "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
        );
    }

    #[test]
    fn hashcat_wif_decodes() {
        let text = "KxhashcatxhXkULNJYF8Fu46G28SJrC7x2qwFtRuf38kVjkWxHg3";
        let decoded = base58_decode(text).unwrap();
        assert_eq!(decoded.len(), 38);
        assert_eq!(
            crate::format::hex(&decoded[1..33]),
            "2c2d44500325a1234252c608ce4b547d3f794ec6db134d900927d0a700d1728d"
        );
        assert_eq!(
            wif_key(text).unwrap().0,
            "1Jv6EonXm9x4Dw4QjEPAhGfmzFxTL7b3Zj"
        );
    }
}
