//! Ethereum keystore and pre-sale wallet extraction.

use std::str;

use serde_json::Value;

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::parse;
use crate::types::{EthereumPbkdf2, EthereumPresale, EthereumScrypt};
use crate::{HashType, HashValue};

pub struct EthereumPbkdf2Extractor;
pub struct EthereumScryptExtractor;
pub struct EthereumPresaleExtractor;

enum Wallet {
    Pbkdf2(EthereumPbkdf2),
    Scrypt(EthereumScrypt),
    Presale(EthereumPresale),
}

fn json(artifact: &Artifact) -> Result<Value, ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    let text = str::from_utf8(&data)
        .map_err(|_| ExtractError::Invalid("Ethereum wallet is not UTF-8".to_owned()))?;
    serde_json::from_str(text)
        .map_err(|error| ExtractError::Invalid(format!("invalid Ethereum JSON: {error}")))
}

fn hex(value: &Value, field: &str) -> Result<Vec<u8>, ExtractError> {
    let value = value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| ExtractError::Invalid(format!("missing Ethereum `{field}`")))?;
    parse::decode_hex(value, 0)
        .map_err(|error| ExtractError::Invalid(format!("invalid Ethereum `{field}`: {error}")))
}

fn number(value: &Value, field: &str) -> Result<u32, ExtractError> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| ExtractError::Invalid(format!("invalid Ethereum `{field}`")))
}

fn parse_wallet(artifact: &Artifact) -> Result<Wallet, ExtractError> {
    let data = json(artifact)?;
    let Some(crypto) = data.get("crypto").or_else(|| data.get("Crypto")) else {
        let encrypted_seed = hex(&data, "encseed")?;
        let address = hex(&data, "ethaddr")?;
        let address = address.try_into().map_err(|_| {
            ExtractError::Invalid("Ethereum pre-sale address must be 20 bytes".to_owned())
        })?;
        let mac = hex(&data, "bkp")?;
        let mac = mac
            .get(..16)
            .and_then(|mac| mac.try_into().ok())
            .ok_or_else(|| {
                ExtractError::Invalid("Ethereum pre-sale bkp must be at least 16 bytes".to_owned())
            })?;
        return Ok(Wallet::Presale(EthereumPresale {
            encrypted_seed,
            address,
            mac,
        }));
    };
    if crypto.get("cipher").and_then(Value::as_str) != Some("aes-128-ctr") {
        return Err(ExtractError::Unsupported(
            "unsupported Ethereum cipher".to_owned(),
        ));
    }
    let ciphertext = hex(crypto, "ciphertext")?;
    let mac = hex(crypto, "mac")?;
    let kdf = crypto
        .get("kdf")
        .and_then(Value::as_str)
        .ok_or_else(|| ExtractError::Invalid("missing Ethereum KDF".to_owned()))?;
    let params = crypto
        .get("kdfparams")
        .ok_or_else(|| ExtractError::Invalid("missing Ethereum KDF parameters".to_owned()))?;
    let salt = hex(params, "salt")?;
    match kdf {
        "pbkdf2" => {
            if params.get("prf").and_then(Value::as_str) != Some("hmac-sha256") {
                return Err(ExtractError::Unsupported(
                    "unsupported Ethereum PBKDF2 PRF".to_owned(),
                ));
            }
            Ok(Wallet::Pbkdf2(EthereumPbkdf2 {
                iterations: number(params, "c")?,
                salt,
                ciphertext,
                mac,
            }))
        }
        "scrypt" => Ok(Wallet::Scrypt(EthereumScrypt {
            n: number(params, "n")?,
            r: number(params, "r")?,
            p: number(params, "p")?,
            salt,
            ciphertext,
            mac,
        })),
        other => Err(ExtractError::Unsupported(format!(
            "unsupported Ethereum KDF `{other}`"
        ))),
    }
}

fn extract<T>(
    artifact: &Artifact,
    pick: impl FnOnce(Wallet) -> Option<T>,
) -> Result<T, ExtractError> {
    let wallet = parse_wallet(artifact)?;
    pick(wallet)
        .ok_or_else(|| ExtractError::Unsupported("different Ethereum wallet type".to_owned()))
}

impl Extractor for EthereumPbkdf2Extractor {
    fn slug(&self) -> &'static str {
        EthereumPbkdf2::SLUG
    }
    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse_wallet(artifact) {
            Ok(Wallet::Pbkdf2(_)) => Probe::yes("Ethereum PBKDF2 keystore"),
            _ => Probe::No,
        }
    }
    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let value = extract(artifact, |wallet| match wallet {
            Wallet::Pbkdf2(v) => Some(v),
            _ => None,
        })?;
        Ok(vec![Box::new(value) as Box<dyn HashValue>])
    }
}

impl Extractor for EthereumScryptExtractor {
    fn slug(&self) -> &'static str {
        EthereumScrypt::SLUG
    }
    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse_wallet(artifact) {
            Ok(Wallet::Scrypt(_)) => Probe::yes("Ethereum scrypt keystore"),
            _ => Probe::No,
        }
    }
    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let value = extract(artifact, |wallet| match wallet {
            Wallet::Scrypt(v) => Some(v),
            _ => None,
        })?;
        Ok(vec![Box::new(value) as Box<dyn HashValue>])
    }
}

impl Extractor for EthereumPresaleExtractor {
    fn slug(&self) -> &'static str {
        EthereumPresale::SLUG
    }
    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse_wallet(artifact) {
            Ok(Wallet::Presale(_)) => Probe::yes("Ethereum pre-sale wallet"),
            _ => Probe::No,
        }
    }
    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let value = extract(artifact, |wallet| match wallet {
            Wallet::Presale(v) => Some(v),
            _ => None,
        })?;
        Ok(vec![Box::new(value) as Box<dyn HashValue>])
    }
}
