//! ENCDataVault vault extraction.

use std::path::Path;

use super::{Artifact, ExtractError, Extracted, Extractor, MemberRole, Probe, ReadAt};
use crate::types::Encdv;
use crate::{HashType, HashValue};

const MAGIC: [u8; 4] = [0xd2, 0xc3, 0xb4, 0xa1];
const HEADER_SIZE: usize = 28;
const KEYCHAIN_TAIL_SIZE: usize = 132;
const KEYCHAIN_SIZE: u32 = 128;

pub struct EncdvExtractor;

fn label_name(label: &str) -> String {
    Path::new(label)
        .file_name()
        .map_or_else(
            || label.to_owned(),
            |name| name.to_string_lossy().into_owned(),
        )
        .to_ascii_lowercase()
}

fn member_named<'a>(artifact: &'a Artifact, target: &str) -> Option<&'a dyn ReadAt> {
    artifact.members().iter().find_map(|member| {
        let name = match &member.role {
            MemberRole::Primary => label_name(artifact.label()),
            MemberRole::Named(role) => role.to_ascii_lowercase(),
        };
        let stem = name.strip_suffix(".dat").unwrap_or(&name);
        let matches = stem == target
            || stem
                .strip_prefix(target)
                .is_some_and(|suffix| suffix.starts_with('-'));
        matches.then_some(&*member.source)
    })
}

fn read_u32_be(data: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

struct Header {
    parameter: u8,
    salt: [u8; 8],
    check: [u8; 8],
}

fn header(source: &dyn ReadAt) -> Result<Header, ExtractError> {
    if source.len() < HEADER_SIZE as u64 {
        return Err(ExtractError::Invalid(
            "ENCDataVault header is too small".to_owned(),
        ));
    }
    let mut data = [0u8; HEADER_SIZE];
    source.read_exact_at(0, &mut data).map_err(|error| {
        ExtractError::Invalid(format!("cannot read ENCDataVault header: {error}"))
    })?;
    if data[..4] != MAGIC {
        return Err(ExtractError::Unsupported(
            "ENCDataVault header not found".to_owned(),
        ));
    }
    let parameter = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    let parameter = u8::try_from(parameter).map_err(|_| {
        ExtractError::Invalid("ENCDataVault cipher parameter is invalid".to_owned())
    })?;
    Ok(Header {
        parameter,
        salt: data[12..20].try_into().expect("eight-byte salt"),
        check: data[20..28].try_into().expect("eight-byte check value"),
    })
}

fn pbkdf2_extra(source: &dyn ReadAt) -> Result<String, ExtractError> {
    let len = source.len();
    if len <= 12 {
        return Err(ExtractError::Invalid(
            "ENCDataVault enckey.dat is too small".to_owned(),
        ));
    }
    let mut prefix = [0u8; 8];
    source.read_exact_at(0, &mut prefix).map_err(|error| {
        ExtractError::Invalid(format!("cannot read ENCDataVault enckey.dat: {error}"))
    })?;
    let length = u64::from(read_u32_be(&prefix, 4));
    if length == 0 || length + 12 > len {
        return Err(ExtractError::Invalid(
            "ENCDataVault enckey.dat salt length is invalid".to_owned(),
        ));
    }
    let mut salt = vec![0; usize::try_from(length).expect("salt length fits in memory")];
    source.read_exact_at(8, &mut salt).map_err(|error| {
        ExtractError::Invalid(format!("cannot read ENCDataVault salt: {error}"))
    })?;
    let mut iterations = [0u8; 4];
    source
        .read_exact_at(8 + length, &mut iterations)
        .map_err(|error| {
            ExtractError::Invalid(format!("cannot read ENCDataVault iterations: {error}"))
        })?;
    Ok(format!(
        "{length}${}${}",
        crate::format::hex(&salt),
        read_u32_be(&iterations, 0)
    ))
}

fn keychain_extra(source: &dyn ReadAt) -> Result<String, ExtractError> {
    if source.len() < KEYCHAIN_TAIL_SIZE as u64 {
        return Err(ExtractError::Invalid(
            "ENCDataVault keychain.dat is too small".to_owned(),
        ));
    }
    let mut tail = [0u8; KEYCHAIN_TAIL_SIZE];
    source
        .read_exact_at(source.len() - KEYCHAIN_TAIL_SIZE as u64, &mut tail)
        .map_err(|error| {
            ExtractError::Invalid(format!("cannot read ENCDataVault keychain: {error}"))
        })?;
    if read_u32_be(&tail, 0) != KEYCHAIN_SIZE {
        return Err(ExtractError::Invalid(
            "ENCDataVault keychain length is invalid".to_owned(),
        ));
    }
    Ok(crate::format::hex(&tail[4..]))
}

fn parse(artifact: &Artifact) -> Result<Encdv, ExtractError> {
    let filesystem = member_named(artifact, "filesystem");
    let index = member_named(artifact, "index");
    let keychain = member_named(artifact, "keychain");
    let (source, version) = if let Some(source) = filesystem {
        (source, 1)
    } else if let Some(source) = index {
        (source, 3)
    } else if keychain.is_some() {
        (artifact.primary(), 3)
    } else {
        (artifact.primary(), 1)
    };
    let header = header(source)?;

    let mut extra = String::new();
    let scheme = if let Some(enckey) = member_named(artifact, "enckey") {
        extra = pbkdf2_extra(enckey)?;
        "encdv-pbkdf2"
    } else {
        "encdv"
    };

    if version == 3 {
        let keychain = keychain.ok_or_else(|| {
            ExtractError::Unsupported("ENCDataVault keychain.dat is required".to_owned())
        })?;
        let keychain = keychain_extra(keychain)?;
        if !extra.is_empty() {
            extra.push('$');
        }
        extra.push_str(&keychain);
    }

    Ok(Encdv {
        scheme: scheme.to_owned(),
        version,
        parameter: header.parameter,
        salt: header.salt,
        check: header.check,
        extra,
    })
}

impl Extractor for EncdvExtractor {
    fn slug(&self) -> &'static str {
        Encdv::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse(artifact) {
            Ok(_) => Probe::yes("ENCDataVault encrypted vault header"),
            Err(_) => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(vec![Box::new(parse(artifact)?) as Box<dyn HashValue>])
    }
}
