//! OpenPGP secret-key and symmetrically encrypted file extraction.

use std::io::{Cursor, Read};

use pgp::armor::Dearmor;
use pgp::packet::{Packet, PacketParser};
use pgp::types::{
    EcdhPublicParams, PublicKeyTrait, PublicParams, S2kParams, SecretParams, StringToKey,
};

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Pgp;
use crate::{HashType, HashValue};

pub struct PgpExtractor;

struct SymmetricSession {
    s2k_type: u8,
    s2k_hash: u32,
    cipher: u8,
    iterations: u32,
    salt: Vec<u8>,
}

fn skip_space(data: &[u8], mut pos: usize) -> usize {
    while pos < data.len() && data[pos].is_ascii_whitespace() {
        pos += 1;
    }
    pos
}

fn quoted(data: &[u8], pos: usize) -> Option<(Vec<u8>, usize)> {
    if data.get(pos) != Some(&b'"') {
        return None;
    }
    let end = pos + 1 + data.get(pos + 1..)?.iter().position(|byte| *byte == b'"')?;
    Some((data[pos + 1..end].to_vec(), end + 1))
}

fn hash_hex(data: &[u8], pos: usize) -> Option<(Vec<u8>, usize)> {
    if data.get(pos) != Some(&b'#') {
        return None;
    }
    let end = pos + 1 + data.get(pos + 1..)?.iter().position(|byte| *byte == b'#')?;
    let compact = data[pos + 1..end]
        .iter()
        .filter(|byte| !byte.is_ascii_whitespace())
        .copied()
        .collect::<Vec<_>>();
    let text = std::str::from_utf8(&compact).ok()?;
    Some((crate::parse::decode_hex(text, 0).ok()?, end + 1))
}

fn token(data: &[u8], pos: usize) -> Option<(Vec<u8>, usize)> {
    quoted(data, pos).or_else(|| hash_hex(data, pos))
}

fn pgp_ocb(data: &[u8]) -> Option<Pgp> {
    let marker = data
        .windows(b"openpgp-s2k3-ocb-aes".len())
        .position(|window| window == b"openpgp-s2k3-ocb-aes")?;
    let sha = data[marker..]
        .windows(5)
        .position(|window| window == b"(sha1")?
        + marker
        + 5;
    let mut pos = skip_space(data, sha);
    let (salt, next) = token(data, pos)?;
    if !matches!(salt.len(), 8 | 16) {
        return None;
    }
    pos = skip_space(data, next);
    let (iterations, next) = if data.get(pos) == Some(&b'"') {
        let (value, next) = quoted(data, pos)?;
        (String::from_utf8(value).ok()?.parse::<u32>().ok()?, next)
    } else {
        let end = data[pos..]
            .iter()
            .position(|byte| *byte == b')' || byte.is_ascii_whitespace())
            .map(|offset| pos + offset)?;
        let value = std::str::from_utf8(&data[pos..end])
            .ok()?
            .parse::<u32>()
            .ok()?;
        (value, end)
    };
    let close = data[next..].iter().position(|byte| *byte == b')')? + next + 1;
    pos = skip_space(data, close);
    let (nonce, next) = token(data, pos)?;
    if nonce.len() != 12 {
        return None;
    }
    pos = skip_space(data, next);
    if data.get(pos) == Some(&b')') {
        pos = skip_space(data, pos + 1);
    }
    let (ciphertext, _) = token(data, pos)?;
    if ciphertext.len() < 16 {
        return None;
    }
    Some(Pgp {
        algorithm: 1,
        encrypted_size: u32::try_from(ciphertext.len()).ok()?,
        modulus_size: 4096,
        encrypted_data: ciphertext,
        s2k_type: 1,
        s2k_mode: 254,
        s2k_hash: 2,
        cipher: 7,
        iv_size: 12,
        iv: nonce,
        iterations,
        salt,
    })
}

impl Extractor for PgpExtractor {
    fn slug(&self) -> &'static str {
        Pgp::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        let data = match artifact.primary().read_all() {
            Ok(data) => data,
            Err(error) => return Probe::maybe(format!("cannot read artifact: {error}")),
        };
        if pgp_ocb(&data).is_some() {
            return Probe::yes("GnuPG agent OCB private key");
        }
        let armored = armor_start(&data).is_some();
        if !armored && data.first().is_none_or(|first| first & 0x80 == 0) {
            return Probe::No;
        }
        let data = match dearmor(&data) {
            Ok(data) => data,
            Err(error) => return Probe::maybe(error.to_string()),
        };

        let mut saw_packet = false;
        let mut saw_symmetric_session = false;
        for packet in PacketParser::new(data.as_slice()) {
            match packet {
                Ok(Packet::SecretKey(_) | Packet::SecretSubkey(_)) => {
                    return Probe::yes("OpenPGP secret-key packet");
                }
                Ok(Packet::SymKeyEncryptedSessionKey(_)) => {
                    saw_symmetric_session = true;
                    saw_packet = true;
                }
                Ok(Packet::SymEncryptedData(_) | Packet::SymEncryptedProtectedData(_))
                    if saw_symmetric_session =>
                {
                    return Probe::yes("OpenPGP symmetrically encrypted file");
                }
                Ok(_) => saw_packet = true,
                Err(error) if armored || saw_packet => {
                    return Probe::maybe(format!("invalid OpenPGP packet: {error}"));
                }
                Err(_) => return Probe::No,
            }
        }
        Probe::No
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let data = artifact.primary().read_all().map_err(|error| {
            ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
        })?;
        if let Some(hash) = pgp_ocb(&data) {
            return Ok(vec![Box::new(hash) as Box<dyn HashValue>]);
        }
        let data = dearmor(&data)?;
        let mut hashes = Vec::new();
        let mut pending_symmetric = None;

        for packet in PacketParser::new(data.as_slice()) {
            let packet = packet.map_err(|error| {
                ExtractError::Invalid(format!("invalid OpenPGP packet: {error}"))
            })?;
            match packet {
                Packet::SecretKey(key) => match key.secret_params() {
                    SecretParams::Encrypted(secret) => {
                        hashes
                            .push(Box::new(convert(key.public_params(), secret)?)
                                as Box<dyn HashValue>);
                    }
                    SecretParams::Plain(_) => {}
                },
                Packet::SecretSubkey(key) => match key.secret_params() {
                    SecretParams::Encrypted(secret) => {
                        hashes
                            .push(Box::new(convert(key.public_params(), secret)?)
                                as Box<dyn HashValue>);
                    }
                    SecretParams::Plain(_) => {}
                },
                Packet::SymKeyEncryptedSessionKey(key) => {
                    pending_symmetric = Some(symmetric_session(key)?);
                }
                Packet::SymEncryptedData(data) => {
                    let session = pending_symmetric.take().ok_or_else(|| {
                        ExtractError::Unsupported(
                            "OpenPGP encrypted data has no symmetric session key".to_owned(),
                        )
                    })?;
                    hashes
                        .push(Box::new(symmetric_hash(session, 9, data.data())?)
                            as Box<dyn HashValue>);
                }
                Packet::SymEncryptedProtectedData(data) => {
                    let session = pending_symmetric.take().ok_or_else(|| {
                        ExtractError::Unsupported(
                            "OpenPGP encrypted data has no symmetric session key".to_owned(),
                        )
                    })?;
                    hashes.push(Box::new(symmetric_hash(
                        session,
                        18,
                        protected_payload(data.data())?,
                    )?) as Box<dyn HashValue>);
                }
                _ => {}
            }
        }

        if hashes.is_empty() {
            return Err(ExtractError::Unsupported(
                "no encrypted OpenPGP secret-key or symmetric packet found".to_owned(),
            ));
        }

        Ok(hashes)
    }
}

struct StringToKeyFields {
    kind: u8,
    hash: u32,
    salt: Vec<u8>,
    iterations: u32,
}

fn string_to_key(s2k: &StringToKey) -> Result<StringToKeyFields, ExtractError> {
    match s2k {
        StringToKey::IteratedAndSalted {
            hash_alg,
            salt,
            count,
        } => Ok(StringToKeyFields {
            kind: 3,
            hash: u32::from(hash_algorithm(*hash_alg)),
            salt: salt.to_vec(),
            iterations: (16 + u32::from(count & 15)) << (u32::from(count >> 4) + 6),
        }),
        other => Err(ExtractError::Unsupported(format!(
            "unsupported OpenPGP string-to-key type {other:?}"
        ))),
    }
}

fn symmetric_session(
    key: pgp::packet::SymKeyEncryptedSessionKey,
) -> Result<SymmetricSession, ExtractError> {
    let s2k = string_to_key(key.s2k())?;
    Ok(SymmetricSession {
        s2k_type: s2k.kind,
        s2k_hash: s2k.hash,
        cipher: symmetric_algorithm(key.sym_algorithm()),
        iterations: s2k.iterations,
        salt: s2k.salt,
    })
}

fn protected_payload(data: &pgp::packet::Data) -> Result<&[u8], ExtractError> {
    match data {
        pgp::packet::Data::V1 { data } => Ok(data),
        _ => Err(ExtractError::Unsupported(
            "OpenPGP AEAD protected data is not serialized".to_owned(),
        )),
    }
}

fn symmetric_hash(session: SymmetricSession, usage: u8, data: &[u8]) -> Result<Pgp, ExtractError> {
    Ok(Pgp {
        algorithm: 0,
        encrypted_size: u32::try_from(data.len())
            .map_err(|_| ExtractError::Invalid("OpenPGP encrypted data is too large".to_owned()))?,
        modulus_size: 0,
        encrypted_data: data.to_vec(),
        s2k_type: session.s2k_type,
        s2k_mode: usage,
        s2k_hash: session.s2k_hash,
        cipher: session.cipher,
        iv_size: 0,
        iv: Vec::new(),
        iterations: session.iterations,
        salt: session.salt,
    })
}

const ARMOR_BEGIN: &[u8] = b"-----BEGIN PGP ";

fn armor_start(data: &[u8]) -> Option<usize> {
    data.windows(ARMOR_BEGIN.len())
        .position(|window| window == ARMOR_BEGIN)
}

fn dearmor(data: &[u8]) -> Result<Vec<u8>, ExtractError> {
    let Some(start) = armor_start(data) else {
        return Ok(data.to_vec());
    };

    let mut decoded = Vec::new();
    Dearmor::new(Cursor::new(&data[start..]))
        .read_to_end(&mut decoded)
        .map_err(|error| ExtractError::Invalid(format!("invalid OpenPGP armor: {error}")))?;
    Ok(decoded)
}

fn convert(
    public: &PublicParams,
    secret: &pgp::types::EncryptedSecretParams,
) -> Result<Pgp, ExtractError> {
    let (algorithm, modulus_size) = match public {
        PublicParams::RSA { n, e: _ } => (1, bit_length(n)),
        PublicParams::DSA {
            p,
            q: _,
            g: _,
            y: _,
        } => (17, bit_length(p)),
        PublicParams::ECDSA(params) => {
            let p = match params {
                pgp::types::EcdsaPublicParams::P256 { key: _, p } => p,
                pgp::types::EcdsaPublicParams::P384 { key: _, p } => p,
                pgp::types::EcdsaPublicParams::P521 { key: _, p } => p,
                pgp::types::EcdsaPublicParams::Secp256k1 { key: _, p } => p,
                pgp::types::EcdsaPublicParams::Unsupported { curve: _, p } => p,
            };
            (19, bit_length(p))
        }
        PublicParams::ECDH(params) => match params {
            EcdhPublicParams::Known { p, .. } => (18, bit_length(p)),
            EcdhPublicParams::Unsupported { opaque, .. } => (18, opaque.len() * 8),
        },
        PublicParams::Elgamal { p, g: _, y: _ } => (16, bit_length(p)),
        PublicParams::EdDSALegacy { curve: _, q } => (18, bit_length(q)),
        PublicParams::Ed25519 { public } => (18, public.len() * 8),
        PublicParams::X25519 { public } => (18, public.len() * 8),
        PublicParams::X448 { public } => (18, public.len() * 8),
        PublicParams::Unknown { .. } => {
            return Err(ExtractError::Unsupported(
                "unknown OpenPGP public-key parameters".to_owned(),
            ));
        }
    };

    let (s2k, cipher, iv) = match secret.string_to_key_params() {
        S2kParams::Cfb { sym_alg, s2k, iv } | S2kParams::MalleableCfb { sym_alg, s2k, iv } => {
            (s2k, *sym_alg, iv)
        }
        _ => {
            return Err(ExtractError::Unsupported(
                "unsupported OpenPGP secret-key encryption mode".to_owned(),
            ));
        }
    };
    let s2k = string_to_key(s2k)?;
    let data = secret.data();

    Ok(Pgp {
        algorithm,
        encrypted_size: u32::try_from(data.len())
            .map_err(|_| ExtractError::Invalid("OpenPGP secret data is too large".to_owned()))?,
        modulus_size: u32::try_from(modulus_size)
            .map_err(|_| ExtractError::Invalid("OpenPGP key is too large".to_owned()))?,
        encrypted_data: data.to_vec(),
        s2k_type: s2k.kind,
        s2k_hash: s2k.hash,
        s2k_mode: secret.string_to_key_id(),
        cipher: symmetric_algorithm(cipher),
        iv_size: u8::try_from(iv.len())
            .map_err(|_| ExtractError::Invalid("OpenPGP IV is too large".to_owned()))?,
        iv: iv.to_vec(),
        iterations: s2k.iterations,
        salt: s2k.salt,
    })
}

fn bit_length(value: &pgp::types::Mpi) -> usize {
    value.as_bytes().len() * 8
}

fn hash_algorithm(hash: pgp::crypto::hash::HashAlgorithm) -> u8 {
    use pgp::crypto::hash::HashAlgorithm;
    match hash {
        HashAlgorithm::MD5 => 1,
        HashAlgorithm::SHA1 => 2,
        HashAlgorithm::RIPEMD160 => 3,
        HashAlgorithm::SHA2_256 => 8,
        HashAlgorithm::SHA2_384 => 9,
        HashAlgorithm::SHA2_512 => 10,
        HashAlgorithm::SHA2_224 => 11,
        _ => 0,
    }
}

fn symmetric_algorithm(algorithm: pgp::crypto::sym::SymmetricKeyAlgorithm) -> u8 {
    use pgp::crypto::sym::SymmetricKeyAlgorithm;
    match algorithm {
        SymmetricKeyAlgorithm::IDEA => 1,
        SymmetricKeyAlgorithm::TripleDES => 2,
        SymmetricKeyAlgorithm::CAST5 => 3,
        SymmetricKeyAlgorithm::Blowfish => 4,
        SymmetricKeyAlgorithm::AES128 => 7,
        SymmetricKeyAlgorithm::AES192 => 8,
        SymmetricKeyAlgorithm::AES256 => 9,
        SymmetricKeyAlgorithm::Twofish => 10,
        SymmetricKeyAlgorithm::Camellia128 => 11,
        SymmetricKeyAlgorithm::Camellia192 => 12,
        SymmetricKeyAlgorithm::Camellia256 => 13,
        _ => 0,
    }
}
