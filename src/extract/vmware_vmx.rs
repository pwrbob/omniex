//! VMware VMX hashcat metadata extraction.

use std::str;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use omniex::extract::{Artifact, ExtractError, Extracted, Extractor, Probe};
use omniex::types::VmwareVmx;
use omniex::{HashType, HashValue};

pub struct VmwareVmxExtractor;

fn percent_decode(value: &str) -> Vec<u8> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let Ok(decoded) = u8::from_str_radix(&value[index + 1..index + 3], 16) {
                out.push(decoded);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    out
}

fn parse(artifact: &Artifact) -> Result<VmwareVmx, ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    let text = str::from_utf8(&data)
        .map_err(|_| ExtractError::Invalid("VMX file is not UTF-8".to_owned()))?;
    let line = text
        .lines()
        .find(|line| line.contains("encryption.keySafe"))
        .ok_or_else(|| ExtractError::Unsupported("missing VMX encryption.keySafe".to_owned()))?;
    let value = line
        .split_once('=')
        .map(|(_, value)| value.trim().trim_matches('"'))
        .ok_or_else(|| ExtractError::Invalid("invalid VMX keySafe line".to_owned()))?;
    let value = String::from_utf8_lossy(&percent_decode(value)).into_owned();
    let value = value.trim_end_matches(')');

    let id = value
        .split("phrase/")
        .nth(1)
        .and_then(|rest| rest.split('/').next())
        .ok_or_else(|| ExtractError::Unsupported("missing VMX key id".to_owned()))?;
    let field = |name: &str| -> Result<&str, ExtractError> {
        value
            .split(name)
            .nth(1)
            .and_then(|rest| rest.split(':').next())
            .ok_or_else(|| ExtractError::Invalid(format!("missing VMX `{name}`")))
    };
    if field("pass2key=")? != "PBKDF2-HMAC-SHA-1" {
        return Err(ExtractError::Unsupported(
            "unsupported VMX password hashing".to_owned(),
        ));
    }
    if field("cipher=")? != "AES-256" {
        return Err(ExtractError::Unsupported(
            "unsupported VMX cipher".to_owned(),
        ));
    }
    let iterations = field("rounds=")?
        .parse::<u32>()
        .map_err(|_| ExtractError::Invalid("invalid VMX round count".to_owned()))?;
    let salt_part = value
        .split("salt=")
        .nth(1)
        .ok_or_else(|| ExtractError::Invalid("missing VMX salt".to_owned()))?;
    let mut parts = salt_part.split(',');
    let salt = parts
        .next()
        .ok_or_else(|| ExtractError::Invalid("missing VMX salt".to_owned()))?;
    let config_hash = parts
        .next()
        .ok_or_else(|| ExtractError::Invalid("missing VMX config hash".to_owned()))?;
    let cipherdata = parts
        .next()
        .ok_or_else(|| ExtractError::Invalid("missing VMX cipher data".to_owned()))?
        .trim_end_matches(')');
    if config_hash != "HMAC-SHA-1" {
        return Err(ExtractError::Unsupported(
            "unsupported VMX configuration hash".to_owned(),
        ));
    }
    let _id = STANDARD
        .decode(id)
        .map_err(|_| ExtractError::Invalid("invalid VMX key id base64".to_owned()))?;
    let salt = STANDARD
        .decode(salt)
        .map_err(|_| ExtractError::Invalid("invalid VMX salt base64".to_owned()))?;
    let salt: [u8; 16] = salt
        .try_into()
        .map_err(|_| ExtractError::Invalid("invalid VMX salt length".to_owned()))?;
    let cipherdata = STANDARD
        .decode(cipherdata)
        .map_err(|_| ExtractError::Invalid("invalid VMX cipher data base64".to_owned()))?;
    let digest: [u8; 32] = cipherdata
        .get(..32)
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| ExtractError::Invalid("truncated VMX cipher data".to_owned()))?;

    Ok(VmwareVmx {
        version: 0,
        iterations,
        salt,
        digest,
    })
}

impl Extractor for VmwareVmxExtractor {
    fn slug(&self) -> &'static str {
        VmwareVmx::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse(artifact) {
            Ok(_) => Probe::yes("VMware VMX encryption.keySafe"),
            Err(_) => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(vec![Box::new(parse(artifact)?) as Box<dyn HashValue>])
    }
}
