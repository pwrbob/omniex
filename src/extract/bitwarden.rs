//! Bitwarden local data extraction.

use std::collections::HashSet;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Bitwarden;
use crate::{HashType, HashValue};

pub struct BitwardenExtractor;

fn string<'a>(value: &'a Value, names: &[&str]) -> Option<&'a str> {
    names
        .iter()
        .find_map(|name| value.get(*name).and_then(Value::as_str))
}

fn number(value: &Value, names: &[&str]) -> Option<u32> {
    names
        .iter()
        .find_map(|name| value.get(*name).and_then(Value::as_u64))
        .and_then(|value| u32::try_from(value).ok())
}

fn build(
    email: &str,
    iterations: u32,
    key_hash: &str,
    legacy: bool,
) -> Result<Bitwarden, ExtractError> {
    if email.is_empty() {
        return Err(ExtractError::Invalid(
            "Bitwarden account email is empty".to_owned(),
        ));
    }
    if iterations == 0 {
        return Err(ExtractError::Invalid(
            "Bitwarden iteration count must be positive".to_owned(),
        ));
    }
    let digest = STANDARD
        .decode(key_hash)
        .map_err(|_| ExtractError::Invalid("invalid Bitwarden key hash base64".to_owned()))?;
    if digest.len() != 32 {
        return Err(ExtractError::Invalid(
            "Bitwarden key hash must be 32 bytes".to_owned(),
        ));
    }
    Ok(Bitwarden {
        version: 2,
        iterations,
        kdf: if legacy { 1 } else { 2 },
        salt: email.as_bytes().to_vec(),
        digest,
    })
}

fn profile(value: &Value, out: &mut Vec<Bitwarden>) -> Result<(), ExtractError> {
    if let Some(key_hash) = string(value, &["keyHash", "masterKeyHash"]) {
        let email = string(value, &["email", "userEmail", "rememberedEmail"]).or_else(|| {
            value
                .get("profile")
                .and_then(|profile| string(profile, &["email", "userEmail"]))
        });
        let iterations = number(value, &["kdfIterations", "iterations"]).or_else(|| {
            value
                .get("profile")
                .and_then(|profile| number(profile, &["kdfIterations", "iterations"]))
        });
        match (email, iterations) {
            (Some(email), Some(iterations)) => {
                let legacy = value
                    .get("legacy")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                out.push(build(email, iterations, key_hash, legacy)?);
            }
            _ => {
                return Err(ExtractError::Invalid(
                    "Bitwarden account is missing email or iterations".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

fn user_accounts(value: &Value, out: &mut Vec<Bitwarden>) -> Result<(), ExtractError> {
    let Value::Object(map) = value else {
        return Ok(());
    };
    for (key, entry) in map {
        let Some(id) = key
            .strip_prefix("user_")
            .and_then(|key| key.strip_suffix("_masterPassword_masterKeyHash"))
        else {
            continue;
        };
        let Some(key_hash) = entry.as_str() else {
            continue;
        };
        let accounts = map.get("global_account_accounts");
        let email = accounts
            .and_then(|accounts| accounts.get(id))
            .and_then(|account| string(account, &["email"]))
            .or_else(|| {
                map.get(&format!("user_{id}"))
                    .and_then(|account| account.get("profile"))
                    .and_then(|profile| string(profile, &["email"]))
            });
        let iterations = map
            .get(&format!("user_{id}_kdfConfig_kdfConfig"))
            .and_then(|config| number(config, &["iterations", "kdfIterations"]))
            .or_else(|| number(value, &["kdfIterations", "iterations"]));
        let Some(email) = email else {
            continue;
        };
        let Some(iterations) = iterations else {
            continue;
        };
        let legacy = map.get("legacy").and_then(Value::as_bool).unwrap_or(false);
        out.push(build(email, iterations, key_hash, legacy)?);
    }
    Ok(())
}

fn scan(value: &Value, out: &mut Vec<Bitwarden>) -> Result<(), ExtractError> {
    match value {
        Value::Array(items) => {
            for item in items {
                scan(item, out)?;
            }
        }
        Value::Object(_) => {
            profile(value, out)?;
            user_accounts(value, out)?;
            for (_, item) in value.as_object().into_iter().flatten() {
                scan(item, out)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn parse(artifact: &Artifact) -> Result<Vec<Bitwarden>, ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    let document: Value = serde_json::from_slice(&data)
        .map_err(|error| ExtractError::Invalid(format!("invalid Bitwarden JSON: {error}")))?;
    let mut accounts = Vec::new();
    scan(&document, &mut accounts)?;
    let mut seen = HashSet::new();
    accounts.retain(|account| {
        seen.insert((
            account.salt.clone(),
            account.iterations,
            account.kdf,
            account.digest.clone(),
        ))
    });
    if accounts.is_empty() {
        return Err(ExtractError::Unsupported(
            "no Bitwarden master key hash in artifact".to_owned(),
        ));
    }
    Ok(accounts)
}

impl Extractor for BitwardenExtractor {
    fn slug(&self) -> &'static str {
        Bitwarden::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse(artifact) {
            Ok(_) => Probe::yes("Bitwarden local account data"),
            Err(_) => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(parse(artifact)?
            .into_iter()
            .map(|value| Box::new(value) as Box<dyn HashValue>)
            .collect())
    }
}
