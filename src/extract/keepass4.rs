//! KeePass KDBX v4 database extraction.

use super::{Artifact, CompanionSpec, ExtractError, Extracted, Extractor, Probe};
use crate::types::Keepass4;
use crate::{HashType, HashValue};
use sha2::{Digest, Sha256};

const SIGNATURE_PRIMARY: u32 = 0x9AA2_D903;
const SIGNATURE_SECONDARY: u32 = 0xB54B_FB67;
const SIGNATURE_SECONDARY_PRE: u32 = 0xB54B_FB66;
const VERSION_4: u32 = 0x0004_0000;

const FIELD_MASTER_SEED: u8 = 4;
const FIELD_KDF: u8 = 11;

const VARIANT_TYPE_U32: u8 = 0x04;
const VARIANT_TYPE_U64: u8 = 0x05;
const VARIANT_TYPE_BYTES: u8 = 0x42;

pub struct Keepass4Extractor;

struct Cursor<'a> {
    source: &'a dyn super::ReadAt,
    offset: u64,
    len: u64,
}

impl<'a> Cursor<'a> {
    fn new(source: &'a dyn super::ReadAt) -> Self {
        Self {
            source,
            offset: 0,
            len: source.len(),
        }
    }

    fn bytes(&mut self, count: usize) -> Result<Vec<u8>, ExtractError> {
        let mut data = vec![0; count];
        self.source
            .read_exact_at(self.offset, &mut data)
            .map_err(|error| ExtractError::Invalid(format!("truncated KeePass header: {error}")))?;
        self.offset += count as u64;
        Ok(data)
    }

    fn u8(&mut self) -> Result<u8, ExtractError> {
        Ok(self.bytes(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, ExtractError> {
        let data = self.bytes(4)?;
        Ok(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
    }

    fn remaining(&self) -> u64 {
        self.len.saturating_sub(self.offset)
    }

    fn position(&self) -> u64 {
        self.offset
    }
}

fn little_endian(data: &[u8]) -> u64 {
    let mut value = 0;
    for (shift, byte) in data.iter().take(8).enumerate() {
        value |= u64::from(*byte) << (8 * shift);
    }
    value
}

struct Kdf {
    uuid: Vec<u8>,
    seed: Vec<u8>,
    iterations: u64,
    memory: u64,
    version: u32,
    parallelism: u32,
}

fn kdf_parameters(data: &[u8]) -> Result<Kdf, ExtractError> {
    if data.len() < 2 {
        return Err(ExtractError::Invalid(
            "truncated KeePass KDF parameters".to_owned(),
        ));
    }
    let version = u16::from_le_bytes([data[0], data[1]]);
    if version >> 8 != 1 {
        return Err(ExtractError::Unsupported(
            "unsupported KeePass VariantDictionary version".to_owned(),
        ));
    }
    let mut uuid = None;
    let mut seed = None;
    let mut iterations = None;
    let mut memory = 0;
    let mut kdf_version = 0;
    let mut parallelism = 0;
    let mut offset = 2;
    loop {
        let Some(kind) = data.get(offset).copied() else {
            return Err(ExtractError::Invalid(
                "truncated KeePass KDF parameters".to_owned(),
            ));
        };
        offset += 1;
        if kind == 0 {
            break;
        }
        let key_length = data
            .get(offset..offset + 4)
            .map(little_endian)
            .ok_or_else(|| ExtractError::Invalid("truncated KeePass KDF key".to_owned()))?
            as usize;
        offset += 4;
        let key = data
            .get(offset..offset + key_length)
            .ok_or_else(|| ExtractError::Invalid("truncated KeePass KDF key".to_owned()))?;
        offset += key_length;
        let value_length = data
            .get(offset..offset + 4)
            .map(little_endian)
            .ok_or_else(|| ExtractError::Invalid("truncated KeePass KDF value".to_owned()))?
            as usize;
        offset += 4;
        let value = data
            .get(offset..offset + value_length)
            .ok_or_else(|| ExtractError::Invalid("truncated KeePass KDF value".to_owned()))?;
        offset += value_length;

        match (kind, key) {
            (VARIANT_TYPE_U64, b"R" | b"I") => iterations = Some(little_endian(value)),
            (VARIANT_TYPE_U64, b"M") => memory = little_endian(value),
            (VARIANT_TYPE_U32, b"P") => {
                parallelism = u32::try_from(little_endian(value)).unwrap_or(u32::MAX)
            }
            (VARIANT_TYPE_U32, b"V") => {
                kdf_version = u32::try_from(little_endian(value)).unwrap_or(u32::MAX)
            }
            (VARIANT_TYPE_BYTES, b"$UUID") => uuid = Some(value.to_vec()),
            (VARIANT_TYPE_BYTES, b"S") => seed = Some(value.to_vec()),
            _ => {}
        }
    }

    Ok(Kdf {
        uuid: uuid.ok_or_else(|| ExtractError::Invalid("missing KeePass KDF UUID".to_owned()))?,
        seed: seed.ok_or_else(|| ExtractError::Invalid("missing KeePass KDF seed".to_owned()))?,
        iterations: iterations
            .ok_or_else(|| ExtractError::Invalid("missing KeePass KDF iterations".to_owned()))?,
        memory,
        version: kdf_version,
        parallelism,
    })
}

fn parse(artifact: &Artifact) -> Result<Keepass4, ExtractError> {
    let mut cursor = Cursor::new(artifact.primary());
    if cursor.remaining() < 12 {
        return Err(ExtractError::Invalid(
            "KeePass database is truncated".to_owned(),
        ));
    }
    if cursor.u32()? != SIGNATURE_PRIMARY {
        return Err(ExtractError::Unsupported(
            "missing KeePass signature".to_owned(),
        ));
    }
    let signature = cursor.u32()?;
    if signature != SIGNATURE_SECONDARY && signature != SIGNATURE_SECONDARY_PRE {
        return Err(ExtractError::Unsupported(
            "missing KeePass signature".to_owned(),
        ));
    }
    let version = cursor.u32()?;
    if version & 0xffff_0000 < VERSION_4 {
        return Err(ExtractError::Unsupported(
            "KeePass KDBX v2/v3 database".to_owned(),
        ));
    }

    let mut master_seed = None;
    let mut kdf = None;
    loop {
        let id = cursor.u8()?;
        let size = cursor.u32()? as usize;
        if id == 0 {
            if size != 4 {
                return Err(ExtractError::Invalid(
                    "invalid KeePass end-of-header field".to_owned(),
                ));
            }
            let data = cursor.bytes(size)?;
            if data != [0x0d, 0x0a, 0x0d, 0x0a] {
                return Err(ExtractError::Invalid(
                    "invalid KeePass end-of-header marker".to_owned(),
                ));
            }
            break;
        }
        if size == 0 {
            return Err(ExtractError::Invalid(
                "zero-length KeePass header field".to_owned(),
            ));
        }
        let data = cursor.bytes(size)?;
        match id {
            FIELD_MASTER_SEED => master_seed = Some(data),
            FIELD_KDF => kdf = Some(data),
            _ => {}
        }
    }
    let header_end = cursor.position();

    let master_seed = master_seed
        .ok_or_else(|| ExtractError::Invalid("missing KeePass master seed".to_owned()))?;
    let kdf = kdf_parameters(
        &kdf.ok_or_else(|| ExtractError::Invalid("missing KeePass KDF parameters".to_owned()))?,
    )?;
    if kdf.iterations == 0 {
        return Err(ExtractError::Invalid(
            "KeePass KDF iterations cannot be zero".to_owned(),
        ));
    }
    if kdf.uuid.len() < 4 {
        return Err(ExtractError::Invalid(
            "KeePass KDF UUID is too short".to_owned(),
        ));
    }

    let mut header = vec![0; header_end as usize];
    artifact
        .primary()
        .read_exact_at(0, &mut header)
        .map_err(|error| ExtractError::Invalid(format!("cannot read KeePass header: {error}")))?;

    cursor.bytes(32)?;
    let header_hmac = cursor.bytes(32)?;

    Ok(Keepass4 {
        version: 4,
        iterations: u32::try_from(kdf.iterations).map_err(|_| {
            ExtractError::Invalid("KeePass KDF iterations are too large".to_owned())
        })?,
        kdf_uuid: crate::format::hex(&kdf.uuid[..4]),
        memory: kdf.memory,
        kdf_version: u8::try_from(kdf.version)
            .map_err(|_| ExtractError::Invalid("invalid KeePass KDF version".to_owned()))?,
        parallelism: u8::try_from(kdf.parallelism)
            .map_err(|_| ExtractError::Invalid("invalid KeePass KDF parallelism".to_owned()))?,
        master_seed: crate::format::hex(&master_seed),
        salt: crate::format::hex(&kdf.seed),
        header: crate::format::hex(&header),
        digest: header_hmac
            .as_slice()
            .try_into()
            .map_err(|_| ExtractError::Invalid("invalid KeePass header HMAC".to_owned()))?,
        keyfile: keyfile(artifact)?,
    })
}

fn keyfile_key(data: &[u8]) -> Vec<u8> {
    if let Some(key) = xml_keyfile_key(data) {
        return key;
    }
    let text = String::from_utf8_lossy(data);
    let trimmed = text.trim();
    if trimmed.len() == 64 && trimmed.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        if let Ok(key) = crate::parse::decode_hex(trimmed, 0) {
            return key;
        }
    }
    Sha256::digest(data).to_vec()
}

fn xml_keyfile_key(data: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(data).ok()?;
    let start = text.find("<Data")?;
    let open = text[start..].find('>')? + start;
    let end = text[open + 1..].find("</Data>")? + open + 1;
    let cleaned: String = text[open + 1..end]
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    if cleaned.len() == 64 && cleaned.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return crate::parse::decode_hex(&cleaned, 0).ok();
    }
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(cleaned)
        .ok()?;
    (decoded.len() == 32).then_some(decoded)
}

fn keyfile(artifact: &Artifact) -> Result<String, ExtractError> {
    let Some(source) = artifact.member("keyfile") else {
        return Ok(String::new());
    };
    let mut data = vec![0; source.len() as usize];
    source
        .read_exact_at(0, &mut data)
        .map_err(|error| ExtractError::Invalid(format!("cannot read KeePass keyfile: {error}")))?;
    Ok(format!("1*64*{}", crate::format::hex(keyfile_key(&data))))
}

const COMPANIONS: &[CompanionSpec] = &[CompanionSpec::optional(
    "keyfile",
    "key file used in addition to the password",
)];

impl Extractor for Keepass4Extractor {
    fn companions(&self) -> &'static [CompanionSpec] {
        COMPANIONS
    }

    fn slug(&self) -> &'static str {
        Keepass4::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        let mut signature = [0; 8];
        match artifact.primary().read_at(0, &mut signature) {
            Ok(8) => {}
            Ok(_) => return Probe::No,
            Err(error) => return Probe::maybe(format!("cannot read artifact: {error}")),
        }
        let primary = u32::from_le_bytes([signature[0], signature[1], signature[2], signature[3]]);
        let secondary =
            u32::from_le_bytes([signature[4], signature[5], signature[6], signature[7]]);
        if primary != SIGNATURE_PRIMARY
            || (secondary != SIGNATURE_SECONDARY && secondary != SIGNATURE_SECONDARY_PRE)
        {
            return Probe::No;
        }
        match parse(artifact) {
            Ok(_) => Probe::yes("KeePass KDBX v4 header"),
            Err(ExtractError::Unsupported(_)) => Probe::No,
            Err(ExtractError::Invalid(reason)) => Probe::maybe(reason),
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(vec![Box::new(parse(artifact)?) as Box<dyn HashValue>])
    }
}

#[cfg(test)]
mod tests {
    use super::keyfile_key;
    use crate::format::hex;

    #[test]
    fn keyfile_key_reads_xml_and_hex_keyfiles() {
        let xml = br#"<KeyFile><Key><Data Hash="50BD7B21">
            4C772D15 A5D58BEC 0C707345 ECEBDFE2
            18F0529A 4882FE3C D48F00E5 4B733073
        </Data></Key></KeyFile>"#;
        assert_eq!(
            hex(keyfile_key(xml)),
            "4c772d15a5d58bec0c707345ecebdfe218f0529a4882fe3cd48f00e54b733073"
        );
        let hex_file = b"4C772D15A5D58BEC0C707345ECEBDFE218F0529A4882FE3CD48F00E54B733073\n";
        assert_eq!(hex(keyfile_key(hex_file)), hex(keyfile_key(xml)));
        let raw = b"not a keyfile";
        assert_eq!(
            hex(keyfile_key(raw)),
            "6e21fb68975420e0e4c0cfcb75f2f5d17fbc7751ce056de07a66a09c288a1c89"
        );
    }
}
