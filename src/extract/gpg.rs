//! OpenPGP secret-key extraction.

use std::io::{Cursor, Read};

use pgp::armor::Dearmor;
use pgp::packet::{Packet, PacketParser};
use pgp::types::{PublicParams, SecretParams, StringToKeyType};

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Gpg;
use crate::{HashType, HashValue};

pub struct GpgExtractor;

impl Extractor for GpgExtractor {
    fn slug(&self) -> &'static str {
        Gpg::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        let source = artifact.primary();
        let mut prefix = [0; 15];
        let read = match source.read_at(0, &mut prefix) {
            Ok(read) => read,
            Err(error) => return Probe::maybe(format!("cannot read artifact: {error}")),
        };
        if &prefix[..read] == b"-----BEGIN PGP " {
            return Probe::yes("OpenPGP armor header");
        }
        let Some(first) = prefix.first().copied().filter(|_| read > 0) else {
            return Probe::No;
        };
        if first & 0x80 == 0 {
            return Probe::No;
        }
        let tag = if first & 0x40 != 0 {
            first & 0x3f
        } else {
            (first >> 2) & 0x0f
        };
        match tag {
            5 | 7 => Probe::yes("OpenPGP secret-key packet header"),
            _ => Probe::maybe(format!("OpenPGP packet tag {tag}, not a secret key")),
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let data = artifact.primary().read_all().map_err(|error| {
            ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
        })?;
        let data = dearmor(&data)?;
        let mut hashes = Vec::new();

        for packet in PacketParser::new(data.as_slice()) {
            let packet = packet.map_err(|error| {
                ExtractError::Invalid(format!("invalid OpenPGP packet: {error}"))
            })?;
            let hash = match packet {
                Packet::SecretKey(key) => match key.secret_params() {
                    SecretParams::Encrypted(secret) => Some(convert(key.public_params(), secret)?),
                    SecretParams::Plain(_) => None,
                },
                Packet::SecretSubkey(key) => match key.secret_params() {
                    SecretParams::Encrypted(secret) => Some(convert(key.public_params(), secret)?),
                    SecretParams::Plain(_) => None,
                },
                _ => continue,
            };
            if let Some(hash) = hash {
                hashes.push(Box::new(hash) as Box<dyn HashValue>);
            }
        }

        if hashes.is_empty() {
            return Err(ExtractError::Unsupported(
                "no encrypted OpenPGP secret-key packet found".to_owned(),
            ));
        }

        Ok(hashes)
    }
}

fn dearmor(data: &[u8]) -> Result<Vec<u8>, ExtractError> {
    if !data.starts_with(b"-----BEGIN PGP ") {
        return Ok(data.to_vec());
    }

    let mut decoded = Vec::new();
    Dearmor::new(Cursor::new(data))
        .read_to_end(&mut decoded)
        .map_err(|error| ExtractError::Invalid(format!("invalid OpenPGP armor: {error}")))?;
    Ok(decoded)
}

fn convert(
    public: &PublicParams,
    secret: &pgp::types::EncryptedSecretParams,
) -> Result<Gpg, ExtractError> {
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
                pgp::types::EcdsaPublicParams::Unsupported { curve: _, p } => p,
            };
            (19, bit_length(p))
        }
        PublicParams::ECDH {
            curve: _,
            p,
            hash: _,
            alg_sym: _,
        } => (18, bit_length(p)),
        PublicParams::Elgamal { p, g: _, y: _ } => (16, bit_length(p)),
        PublicParams::EdDSA { curve: _, q } => (18, bit_length(q)),
    };

    let s2k = secret.string_to_key();
    let s2k_type = match s2k.typ() {
        StringToKeyType::Salted => 1,
        StringToKeyType::IteratedAndSalted => 3,
        other => {
            return Err(ExtractError::Unsupported(format!(
                "unsupported OpenPGP string-to-key type {other:?}"
            )));
        }
    };
    let iterations = s2k.count().ok_or_else(|| {
        ExtractError::Unsupported("OpenPGP string-to-key has no iteration count".to_owned())
    })?;
    let salt = s2k
        .salt()
        .ok_or_else(|| ExtractError::Unsupported("OpenPGP string-to-key has no salt".to_owned()))?;
    let iv = secret.iv();
    let data = secret.data();

    Ok(Gpg {
        algorithm,
        encrypted_size: u32::try_from(data.len())
            .map_err(|_| ExtractError::Invalid("OpenPGP secret data is too large".to_owned()))?,
        modulus_size: u32::try_from(modulus_size)
            .map_err(|_| ExtractError::Invalid("OpenPGP key is too large".to_owned()))?,
        encrypted_data: data.to_vec(),
        s2k_type,
        s2k_hash: u32::from(hash_algorithm(s2k.hash())),
        s2k_mode: secret.string_to_key_id(),
        cipher: symmetric_algorithm(secret.encryption_algorithm()),
        iv_size: u8::try_from(iv.len())
            .map_err(|_| ExtractError::Invalid("OpenPGP IV is too large".to_owned()))?,
        iv: iv.to_vec(),
        iterations: u32::try_from(iterations).map_err(|_| {
            ExtractError::Invalid("OpenPGP iteration count is too large".to_owned())
        })?,
        salt: salt.to_vec(),
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
