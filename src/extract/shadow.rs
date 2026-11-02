//! Unix password hashes from shadow, passwd, and htpasswd style files.

use std::str;

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::{
    Apr1, Bcrypt, BsdiCrypt, DesCrypt, Md5Crypt, Sha1crypt, Sha256Crypt, Sha512Crypt, SunMd5,
    Yescrypt,
};
use crate::{HashType, HashValue, Parse, ParseOptions};

fn candidates(artifact: &Artifact) -> Result<Vec<String>, ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    let text = str::from_utf8(&data)
        .map_err(|_| ExtractError::Invalid("password file is not UTF-8".to_owned()))?;
    let mut values = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let candidate = line.split(':').nth(1).unwrap_or(line).trim();
        if !candidate.is_empty() && candidate != "*" && candidate != "!" && candidate != "x" {
            values.push(candidate.to_owned());
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
    for value in candidates(artifact)? {
        if let Ok(hash) = T::parse(&value, &opts) {
            hashes.push(hash);
        }
    }
    if hashes.is_empty() {
        return Err(ExtractError::Unsupported(
            "no matching password hashes found".to_owned(),
        ));
    }
    Ok(hashes)
}

fn probe<T>(artifact: &Artifact) -> Probe
where
    T: Parse + HashValue + 'static,
{
    match extract::<T>(artifact) {
        Ok(_) => Probe::yes("password hash line"),
        Err(_) => Probe::No,
    }
}

macro_rules! shadow_extractor {
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

shadow_extractor!(DesCryptExtractor, DesCrypt);
shadow_extractor!(Md5CryptExtractor, Md5Crypt);
shadow_extractor!(Apr1Extractor, Apr1);
shadow_extractor!(Sha256CryptExtractor, Sha256Crypt);
shadow_extractor!(Sha512CryptExtractor, Sha512Crypt);
shadow_extractor!(YescryptExtractor, Yescrypt);
shadow_extractor!(BcryptExtractor, Bcrypt);
shadow_extractor!(BsdiCryptExtractor, BsdiCrypt);
shadow_extractor!(SunMd5Extractor, SunMd5);
shadow_extractor!(Sha1cryptExtractor, Sha1crypt);
