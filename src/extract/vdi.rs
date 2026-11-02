//! VirtualBox VDI encryption extraction from .vbox XML.

use std::str;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use roxmltree::Document;

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::parse;
use crate::types::{Vdi, Virtualbox};
use crate::{HashType, HashValue};

pub struct VdiExtractor;
pub struct VirtualboxExtractor;

fn parse(artifact: &Artifact) -> Result<Vdi, ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    let text = str::from_utf8(&data)
        .map_err(|_| ExtractError::Invalid("VirtualBox XML is not UTF-8".to_owned()))?;
    let document = Document::parse(text)
        .map_err(|error| ExtractError::Invalid(format!("invalid VirtualBox XML: {error}")))?;
    let properties = document
        .descendants()
        .filter(|node| node.is_element() && node.has_tag_name("Property"))
        .collect::<Vec<_>>();
    let key_index = properties
        .iter()
        .position(|node| node.attribute("name") == Some("CRYPT/KeyId"))
        .ok_or_else(|| ExtractError::Unsupported("missing VirtualBox CRYPT/KeyId".to_owned()))?;
    let _key_id = properties[key_index]
        .attribute("value")
        .ok_or_else(|| ExtractError::Invalid("missing VirtualBox key id".to_owned()))?;
    let blob = properties
        .get(key_index + 1)
        .and_then(|node| node.attribute("value"))
        .ok_or_else(|| ExtractError::Unsupported("missing VirtualBox key store".to_owned()))?;
    let blob = STANDARD
        .decode(blob.replace("&#13;&#10;", ""))
        .map_err(|_| ExtractError::Invalid("invalid VirtualBox key store base64".to_owned()))?;
    let version = blob
        .get(4..6)
        .and_then(|value| value.try_into().ok())
        .map(u16::from_le_bytes);
    if blob.get(..4) != Some(b"SCNE") || version != Some(0x100) {
        return Err(ExtractError::Unsupported(
            "unsupported VirtualBox key store version".to_owned(),
        ));
    }
    let rest = &blob[6..];
    if rest.len() < 32 + 32 + 4 + 32 + 4 + 32 + 4 + 32 + 4 + 4 {
        return Err(ExtractError::Invalid(
            "truncated VirtualBox key store".to_owned(),
        ));
    }
    let algo = &rest[..32];
    let kdf = &rest[32..64];
    let gen_keylen = u32::from_le_bytes(rest[64..68].try_into().expect("4 bytes"));
    let final_hash = &rest[68..100];
    let keylen = u32::from_le_bytes(rest[100..104].try_into().expect("4 bytes"));
    let salt2 = &rest[104..136];
    let salt2_iter = u32::from_le_bytes(rest[136..140].try_into().expect("4 bytes"));
    let salt1 = &rest[140..172];
    let salt1_iter = u32::from_le_bytes(rest[172..176].try_into().expect("4 bytes"));
    let evp_len = u32::from_le_bytes(rest[176..180].try_into().expect("4 bytes")) as usize;
    let enc_pass = rest.get(180..180 + evp_len).ok_or_else(|| {
        ExtractError::Invalid("truncated VirtualBox encrypted password".to_owned())
    })?;
    let algorithm = std::str::from_utf8(algo)
        .map_err(|_| ExtractError::Invalid("invalid VirtualBox algorithm".to_owned()))?
        .trim_end_matches('\0');
    let kdf = std::str::from_utf8(kdf)
        .map_err(|_| ExtractError::Invalid("invalid VirtualBox KDF".to_owned()))?
        .trim_end_matches('\0');
    if !matches!(algorithm, "AES-XTS128-PLAIN64" | "AES-XTS256-PLAIN64") || kdf != "PBKDF2-SHA256" {
        return Err(ExtractError::Unsupported(
            "unsupported VirtualBox algorithm or KDF".to_owned(),
        ));
    }

    Ok(Vdi {
        fields: format!(
            "{}$sha256${salt1_iter}${salt2_iter}${gen_keylen}${keylen}${}${}${}${}",
            &algorithm.to_ascii_lowercase()[..10],
            crate::format::hex(salt1),
            crate::format::hex(salt2),
            crate::format::hex(enc_pass),
            crate::format::hex(final_hash)
        ),
    })
}

impl Extractor for VdiExtractor {
    fn slug(&self) -> &'static str {
        Vdi::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse(artifact) {
            Ok(_) => Probe::yes("VirtualBox encrypted key store"),
            _ => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(vec![Box::new(parse(artifact)?) as Box<dyn HashValue>])
    }
}

impl Extractor for VirtualboxExtractor {
    fn slug(&self) -> &'static str {
        Virtualbox::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse(artifact) {
            Ok(_) => Probe::yes("VirtualBox encrypted key store"),
            _ => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let vdi = parse(artifact)?;
        let fields = vdi.fields.split('$').collect::<Vec<_>>();
        if fields.len() != 10 {
            return Err(ExtractError::Invalid(
                "invalid VirtualBox fields".to_owned(),
            ));
        }
        let number = |value: &str| {
            value
                .parse::<u32>()
                .map_err(|_| ExtractError::Invalid("invalid VirtualBox numeric field".to_owned()))
        };
        let key_size = u8::try_from(number(fields[5])?)
            .map_err(|_| ExtractError::Invalid("invalid VirtualBox key size".to_owned()))?;
        Ok(vec![Box::new(Virtualbox {
            version: 0,
            iterations: number(fields[2])?,
            salt: parse::decode_hex_field::<32>(fields[6], 0, "salt")
                .map_err(|error| ExtractError::Invalid(error.to_string()))?,
            key_size,
            ciphertext: parse::decode_hex(fields[8], 0)
                .map_err(|error| ExtractError::Invalid(error.to_string()))?,
            second_iterations: number(fields[3])?,
            second_salt: parse::decode_hex_field::<32>(fields[7], 0, "second salt")
                .map_err(|error| ExtractError::Invalid(error.to_string()))?,
            digest: parse::decode_hex_field::<32>(fields[9], 0, "digest")
                .map_err(|error| ExtractError::Invalid(error.to_string()))?,
        }) as Box<dyn HashValue>])
    }
}
