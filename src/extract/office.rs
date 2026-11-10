//! MS Office 2007+ encrypted document extraction.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use byteorder::{ByteOrder, LittleEndian};
use roxmltree::Node;

use super::oldoffice::Cfb;
use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Office;
use crate::{HashType, HashValue};

pub struct OfficeExtractor;

const CFB_SIGNATURE: &[u8] = &[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];

fn attribute<'a>(node: Node<'a, 'a>, name: &str) -> Option<&'a str> {
    node.attributes()
        .find(|attribute| attribute.name() == name)
        .map(|attribute| attribute.value())
}

fn required<'a>(node: Node<'a, 'a>, name: &str) -> Result<&'a str, ExtractError> {
    attribute(node, name)
        .ok_or_else(|| ExtractError::Invalid(format!("missing Office attribute `{name}`")))
}

fn decode_base64(value: &str, name: &str) -> Result<Vec<u8>, ExtractError> {
    STANDARD
        .decode(value)
        .map_err(|error| ExtractError::Invalid(format!("invalid Office {name}: {error}")))
}

fn agile_hashes(xml: &str) -> Result<Vec<Office>, ExtractError> {
    let document = roxmltree::Document::parse(xml)
        .map_err(|error| ExtractError::Invalid(format!("invalid Office XML: {error}")))?;
    let mut hashes = Vec::new();
    for node in document
        .descendants()
        .filter(|node| node.is_element() && node.tag_name().name() == "encryptedKey")
    {
        let spin_count = required(node, "spinCount")?
            .parse::<u32>()
            .map_err(|_| ExtractError::Invalid("invalid Office spin count".to_owned()))?;
        let key_size = required(node, "keyBits")?
            .parse::<u32>()
            .map_err(|_| ExtractError::Invalid("invalid Office key size".to_owned()))?;
        let salt_size = required(node, "saltSize")?
            .parse::<u32>()
            .map_err(|_| ExtractError::Invalid("invalid Office salt size".to_owned()))?;
        let algorithm = required(node, "hashAlgorithm")?;
        let year = match algorithm {
            "SHA1" => 2010,
            "SHA512" => 2013,
            other => {
                return Err(ExtractError::Unsupported(format!(
                    "unsupported Office hash algorithm {other}"
                )));
            }
        };
        let cipher = required(node, "cipherAlgorithm")?;
        if !cipher.contains("AES") {
            return Err(ExtractError::Unsupported(format!(
                "unsupported Office cipher {cipher}"
            )));
        }
        let salt = decode_base64(required(node, "saltValue")?, "salt")?;
        if salt.len() != salt_size as usize {
            return Err(ExtractError::Invalid(
                "Office salt length does not match its header".to_owned(),
            ));
        }
        let verifier = decode_base64(required(node, "encryptedVerifierHashInput")?, "verifier")?;
        let verifier_hash = decode_base64(
            required(node, "encryptedVerifierHashValue")?,
            "verifier hash",
        )?;
        let expected = 32;
        if verifier_hash.len() < expected {
            return Err(ExtractError::Invalid(
                "Office verifier hash is too short".to_owned(),
            ));
        }
        hashes.push(Office {
            year,
            spin_count,
            key_size,
            salt_size,
            salt,
            verifier,
            verifier_hash: verifier_hash[..expected].to_vec(),
        });
    }
    if hashes.is_empty() {
        return Err(ExtractError::Unsupported(
            "Office EncryptionInfo has no password key encryptor".to_owned(),
        ));
    }
    Ok(hashes)
}

fn standard_hash(data: &[u8]) -> Result<Office, ExtractError> {
    let mut cursor = data;
    let mut header_len = LittleEndian::read_u32(cursor);
    cursor = &cursor[4..];
    let _skip_flags = LittleEndian::read_u32(cursor);
    cursor = &cursor[4..];
    header_len = header_len.saturating_sub(4);
    let _size_extra = LittleEndian::read_u32(cursor);
    cursor = &cursor[4..];
    header_len = header_len.saturating_sub(4);
    let _alg_id = LittleEndian::read_u32(cursor);
    cursor = &cursor[4..];
    header_len = header_len.saturating_sub(4);
    let _alg_hash = LittleEndian::read_u32(cursor);
    cursor = &cursor[4..];
    header_len = header_len.saturating_sub(4);
    let key_size = LittleEndian::read_u32(cursor);
    cursor = &cursor[4..];
    header_len = header_len.saturating_sub(4);
    let _provider = LittleEndian::read_u32(cursor);
    cursor = &cursor[4..];
    header_len = header_len.saturating_sub(4);
    let _unused = LittleEndian::read_u32(cursor);
    cursor = &cursor[4..];
    header_len = header_len.saturating_sub(4);
    let _unused = LittleEndian::read_u32(cursor);
    cursor = &cursor[4..];
    header_len = header_len.saturating_sub(4);
    let csp_len = header_len as usize;
    if cursor.len() < csp_len {
        return Err(ExtractError::Invalid(
            "truncated Office encryption header".to_owned(),
        ));
    }
    cursor = &cursor[csp_len..];
    if cursor.len() < 4 {
        return Err(ExtractError::Invalid(
            "truncated Office verifier".to_owned(),
        ));
    }
    let salt_size = LittleEndian::read_u32(cursor);
    cursor = &cursor[4..];
    if salt_size != 16 {
        return Err(ExtractError::Unsupported(format!(
            "unsupported Office salt size {salt_size}"
        )));
    }
    if cursor.len() < 16 + 16 + 4 {
        return Err(ExtractError::Invalid(
            "truncated Office verifier".to_owned(),
        ));
    }
    let salt = cursor[..16].to_vec();
    cursor = &cursor[16..];
    let verifier = cursor[..16].to_vec();
    cursor = &cursor[16..];
    let verifier_hash_size = LittleEndian::read_u32(cursor) as usize;
    cursor = &cursor[4..];
    let verifier_hash = cursor
        .get(..verifier_hash_size)
        .ok_or_else(|| ExtractError::Invalid("truncated Office verifier hash".to_owned()))?
        .to_vec();
    Ok(Office {
        year: 2007,
        spin_count: u32::try_from(verifier_hash_size)
            .map_err(|_| ExtractError::Invalid("Office verifier hash size".to_owned()))?,
        key_size,
        salt_size,
        salt,
        verifier,
        verifier_hash,
    })
}

fn hashes(data: Vec<u8>) -> Result<Vec<Office>, ExtractError> {
    if data.starts_with(b"PK\x03\x04") {
        return Err(ExtractError::Unsupported(
            "Office Open XML document is not encrypted; no password hash to extract".to_owned(),
        ));
    }
    let cfb = Cfb::parse(data)?;
    let stream = cfb
        .stream("EncryptionInfo")
        .ok_or_else(|| ExtractError::Unsupported("missing EncryptionInfo stream".to_owned()))?;
    if stream.len() < 8 {
        return Err(ExtractError::Invalid(
            "truncated EncryptionInfo stream".to_owned(),
        ));
    }
    let major = LittleEndian::read_u16(&stream[0..2]);
    let minor = LittleEndian::read_u16(&stream[2..4]);
    let flags = LittleEndian::read_u32(&stream[4..8]);
    if major == 4 && minor == 4 {
        if flags != 0x40 {
            return Err(ExtractError::Unsupported(
                "unsupported Office agile encryption flags".to_owned(),
            ));
        }
        let xml = String::from_utf8_lossy(&stream[8..]);
        let xml = xml.trim_matches('\0').trim_start_matches('\u{feff}');
        return agile_hashes(xml);
    }
    if flags == 16 {
        return Err(ExtractError::Unsupported(
            "external Office cryptographic providers are not supported".to_owned(),
        ));
    }
    Ok(vec![standard_hash(&stream[8..])?])
}

impl Extractor for OfficeExtractor {
    fn slug(&self) -> &'static str {
        Office::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        let data = match artifact.primary().read_all() {
            Ok(data) => data,
            Err(error) => return Probe::maybe(format!("cannot read artifact: {error}")),
        };
        if data.len() < 512 || &data[..8] != CFB_SIGNATURE {
            return Probe::No;
        }
        match Cfb::parse(data) {
            Ok(cfb) if cfb.has_stream("EncryptionInfo") => {
                Probe::yes("OLE compound file with an EncryptionInfo stream")
            }
            _ => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let data = artifact.primary().read_all().map_err(|error| {
            ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
        })?;
        let hashes = hashes(data)?;
        Ok(hashes
            .into_iter()
            .map(|hash| Box::new(hash) as Box<dyn HashValue>)
            .collect())
    }
}
