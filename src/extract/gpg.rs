//! OpenPGP secret-key and symmetrically encrypted file extraction.

use std::io::{Cursor, Read};

use pgp::armor::Dearmor;
use pgp::packet::{Packet, PacketParser};
use pgp::types::{PublicParams, SecretParams, StringToKeyType};

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Gpg;
use crate::{
    HashType, HashValue, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions,
    parse,
};

pub struct GpgExtractor;

/// OpenPGP symmetrically encrypted file, rendered as
/// `$gpg$*0*<size>*<data>*<s2k type>*<usage>*<s2k hash>*<cipher>*<iterations>*<salt>`.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "GPG symmetric", slug = "gpg", john = ["gpg"])]
struct GpgSymmetric {
    /// Public-key algorithm identifier, always `0` for symmetric files.
    #[field(role = other, encoding = decimal)]
    algorithm: u8,

    /// Encrypted data size in bytes.
    #[field(role = other, encoding = decimal)]
    encrypted_size: u32,

    /// Encrypted data packet.
    #[field(role = ciphertext, encoding = hex)]
    encrypted_data: Vec<u8>,

    /// String-to-key type.
    #[field(role = other, encoding = decimal)]
    s2k_type: u8,

    /// Packet usage identifier: `9` for tag 9, `18` for tag 18.
    #[field(role = other, encoding = decimal)]
    s2k_mode: u8,

    /// String-to-key hash identifier.
    #[field(role = other, encoding = decimal)]
    s2k_hash: u32,

    /// Cipher algorithm identifier.
    #[field(role = other, encoding = decimal)]
    cipher: u8,

    /// String-to-key iteration count.
    #[field(role = iterations, encoding = decimal)]
    iterations: u32,

    /// Eight-byte salt.
    #[field(role = salt, encoding = hex)]
    salt: Vec<u8>,
}

impl Parse for GpgSymmetric {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$gpg$*", 0)?;
        let fields = parse::split_fields(rest, '*', 9)?;
        fn number(value: &str, offset: usize, name: &str) -> Result<u32, ParseError> {
            value.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    offset,
                    format!("invalid GPG {name}"),
                )
            })
        }

        let encrypted_data = parse::decode_hex(fields[2].0, fields[2].1)?;
        if encrypted_data.len() != number(fields[1].0, fields[1].1, "encrypted size")? as usize {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                fields[2].1,
                "GPG encrypted data length does not match its header",
            ));
        }

        Ok(Self {
            algorithm: u8::try_from(number(fields[0].0, fields[0].1, "algorithm")?).map_err(
                |_| parse::error(ParseErrorKind::InvalidCharacter, 6, "invalid GPG algorithm"),
            )?,
            encrypted_size: number(fields[1].0, fields[1].1, "encrypted size")?,
            encrypted_data,
            s2k_type: u8::try_from(number(fields[3].0, fields[3].1, "s2k type")?).map_err(
                |_| {
                    parse::error(
                        ParseErrorKind::InvalidCharacter,
                        fields[3].1,
                        "invalid s2k type",
                    )
                },
            )?,
            s2k_mode: u8::try_from(number(fields[4].0, fields[4].1, "s2k mode")?).map_err(
                |_| {
                    parse::error(
                        ParseErrorKind::InvalidCharacter,
                        fields[4].1,
                        "invalid s2k mode",
                    )
                },
            )?,
            s2k_hash: number(fields[5].0, fields[5].1, "s2k hash")?,
            cipher: u8::try_from(number(fields[6].0, fields[6].1, "cipher")?).map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    fields[6].1,
                    "invalid cipher",
                )
            })?,
            iterations: number(fields[7].0, fields[7].1, "iterations")?,
            salt: parse::decode_hex(fields[8].0, fields[8].1)?,
        })
    }
}

impl Render for GpgSymmetric {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$gpg$*{}*{}*{}*{}*{}*{}*{}*{}*{}",
            self.algorithm,
            self.encrypted_size,
            crate::format::hex(&self.encrypted_data),
            self.s2k_type,
            self.s2k_mode,
            self.s2k_hash,
            self.cipher,
            self.iterations,
            crate::format::hex(&self.salt)
        )
    }
}

struct SymmetricSession {
    s2k_type: u8,
    s2k_hash: u32,
    cipher: u8,
    iterations: u32,
    salt: Vec<u8>,
}

impl Extractor for GpgExtractor {
    fn slug(&self) -> &'static str {
        Gpg::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        let data = match artifact.primary().read_all() {
            Ok(data) => data,
            Err(error) => return Probe::maybe(format!("cannot read artifact: {error}")),
        };
        let armored = data.starts_with(b"-----BEGIN PGP ");
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
                    hashes
                        .push(Box::new(symmetric_hash(session, 18, data.data())?)
                            as Box<dyn HashValue>);
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

fn symmetric_session(
    key: pgp::packet::SymKeyEncryptedSessionKey,
) -> Result<SymmetricSession, ExtractError> {
    let s2k = key.s2k();
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
    Ok(SymmetricSession {
        s2k_type,
        s2k_hash: u32::from(hash_algorithm(s2k.hash())),
        cipher: symmetric_algorithm(key.sym_algorithm()),
        iterations: u32::try_from(iterations).map_err(|_| {
            ExtractError::Invalid("OpenPGP iteration count is too large".to_owned())
        })?,
        salt: salt.to_vec(),
    })
}

fn symmetric_hash(
    session: SymmetricSession,
    usage: u8,
    data: &[u8],
) -> Result<GpgSymmetric, ExtractError> {
    Ok(GpgSymmetric {
        algorithm: 0,
        encrypted_size: u32::try_from(data.len())
            .map_err(|_| ExtractError::Invalid("OpenPGP encrypted data is too large".to_owned()))?,
        encrypted_data: data.to_vec(),
        s2k_type: session.s2k_type,
        s2k_mode: usage,
        s2k_hash: session.s2k_hash,
        cipher: session.cipher,
        iterations: session.iterations,
        salt: session.salt,
    })
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
