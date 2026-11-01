//! Ansible Vault extraction.

use std::str;

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::parse;
use crate::types::AnsibleVault;
use crate::{HashType, HashValue};

pub struct AnsibleVaultExtractor;

const HEADER: &[u8] = b"$ANSIBLE_VAULT";

impl Extractor for AnsibleVaultExtractor {
    fn slug(&self) -> &'static str {
        AnsibleVault::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        let mut prefix = [0; 14];
        match artifact.primary().read_at(0, &mut prefix) {
            Ok(read) if &prefix[..read] == HEADER => Probe::yes("Ansible Vault header"),
            Ok(_) => Probe::No,
            Err(error) => Probe::maybe(format!("cannot read artifact: {error}")),
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let data = artifact.primary().read_all().map_err(|error| {
            ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
        })?;
        let text = str::from_utf8(&data)
            .map_err(|_| ExtractError::Invalid("Ansible Vault file is not UTF-8".to_owned()))?;
        let mut lines = text.lines();
        let header = lines
            .next()
            .ok_or_else(|| ExtractError::Unsupported("empty Ansible Vault file".to_owned()))?;
        let header = header
            .strip_prefix("$ANSIBLE_VAULT;")
            .ok_or_else(|| ExtractError::Unsupported("missing Ansible Vault header".to_owned()))?;
        let (_, cipher) = header
            .split_once(';')
            .ok_or_else(|| ExtractError::Invalid("malformed Ansible Vault header".to_owned()))?;
        if cipher != "AES256" {
            return Err(ExtractError::Unsupported(format!(
                "unsupported Ansible Vault cipher `{cipher}`"
            )));
        }

        let body = lines.map(str::trim).collect::<String>();
        if body.is_empty() {
            return Err(ExtractError::Invalid(
                "Ansible Vault body is empty".to_owned(),
            ));
        }
        let decoded = parse::decode_hex(&body, 0).map_err(|error| {
            ExtractError::Invalid(format!("invalid Ansible Vault body: {error}"))
        })?;
        let decoded = str::from_utf8(&decoded)
            .map_err(|_| ExtractError::Invalid("Ansible Vault body is not ASCII".to_owned()))?;
        let fields = decoded.split('\n').collect::<Vec<_>>();
        if fields.len() != 3 {
            return Err(ExtractError::Invalid(
                "Ansible Vault body must contain salt, HMAC, and ciphertext".to_owned(),
            ));
        }

        let decode = |value: &str, field: &str| {
            parse::decode_hex(value, 0).map_err(|error| {
                ExtractError::Invalid(format!("invalid Ansible Vault {field}: {error}"))
            })
        };
        let salt = decode(fields[0], "salt")?;
        let hmac = decode(fields[1], "HMAC")?;
        let ciphertext = decode(fields[2], "ciphertext")?;
        if salt.len() != 32 {
            return Err(ExtractError::Invalid(
                "Ansible Vault salt must be 32 bytes".to_owned(),
            ));
        }
        if hmac.len() != 32 {
            return Err(ExtractError::Invalid(
                "Ansible Vault HMAC must be 32 bytes".to_owned(),
            ));
        }
        if ciphertext.is_empty() {
            return Err(ExtractError::Invalid(
                "Ansible Vault ciphertext is empty".to_owned(),
            ));
        }

        Ok(vec![Box::new(AnsibleVault {
            version: 0,
            cipher: 0,
            salt: salt.try_into().expect("checked salt length"),
            ciphertext,
            hmac: hmac.try_into().expect("checked HMAC length"),
        }) as Box<dyn HashValue>])
    }
}
