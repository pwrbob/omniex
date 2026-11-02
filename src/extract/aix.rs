//! AIX `/etc/security/passwd` extraction.

use std::str;

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::{AixSmd5, AixSsha1, AixSsha256, AixSsha512};
use crate::{HashType, HashValue, Parse, ParseOptions};

fn values(artifact: &Artifact) -> Result<Vec<String>, ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    let text = str::from_utf8(&data)
        .map_err(|_| ExtractError::Invalid("AIX password file is not UTF-8".to_owned()))?;
    let mut values = Vec::new();
    for line in text.lines() {
        let Some((_, value)) = line.split_once("password = ") else {
            continue;
        };
        let value = value.trim();
        if value != "*" {
            values.push(value.to_owned());
        }
    }
    Ok(values)
}

fn extract<T>(artifact: &Artifact) -> Result<Vec<T>, ExtractError>
where
    T: Parse + HashValue + 'static,
{
    let opts = ParseOptions::default();
    let mut hashes = Vec::new();
    for value in values(artifact)? {
        if let Ok(hash) = T::parse(&value, &opts) {
            hashes.push(hash);
        }
    }
    if hashes.is_empty() {
        return Err(ExtractError::Unsupported(
            "no matching AIX password hashes found".to_owned(),
        ));
    }
    Ok(hashes)
}

fn probe<T>(artifact: &Artifact) -> Probe
where
    T: Parse + HashValue + 'static,
{
    match extract::<T>(artifact) {
        Ok(_) => Probe::yes("AIX password hash"),
        Err(_) => Probe::No,
    }
}

macro_rules! aix_extractor {
    ($name:ident, $ty:ty) => {
        pub struct $name;
        impl Extractor for $name {
            fn slug(&self) -> &'static str {
                <$ty>::SLUG
            }
            fn probe(&self, artifact: &Artifact) -> Probe {
                probe::<$ty>(artifact)
            }
            fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
                Ok(extract::<$ty>(artifact)?
                    .into_iter()
                    .map(|hash| Box::new(hash) as Box<dyn HashValue>)
                    .collect())
            }
        }
    };
}

aix_extractor!(AixSmd5Extractor, AixSmd5);
aix_extractor!(AixSsha1Extractor, AixSsha1);
aix_extractor!(AixSsha256Extractor, AixSsha256);
aix_extractor!(AixSsha512Extractor, AixSsha512);
