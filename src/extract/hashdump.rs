//! Password hashes embedded in text dumps and exports.

use std::str;

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::{
    As400Des, As400Ssha1, LotusNotes, Openvms, Oracle11, Oracle12c, OracleOtm, RacfKdfaes,
    RacfPassphrase, SybaseProp,
};
use crate::{HashType, HashValue, Parse, ParseOptions};

fn tokens(artifact: &Artifact) -> Result<Vec<String>, ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    let text = str::from_utf8(&data)
        .map_err(|_| ExtractError::Invalid("hash dump is not UTF-8".to_owned()))?;
    Ok(text
        .split_whitespace()
        .map(|token| token.trim_matches(|character| matches!(character, '\'' | '"' | ',' | ';')))
        .filter(|token| !token.is_empty())
        .map(str::to_owned)
        .collect())
}

fn extract<T>(artifact: &Artifact) -> Result<Vec<T>, ExtractError>
where
    T: Parse + HashValue + 'static,
{
    let opts = ParseOptions::default();
    let mut hashes = Vec::new();
    for token in tokens(artifact)? {
        if let Ok(hash) = T::parse(&token, &opts) {
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
        Ok(_) => Probe::yes("password hash token"),
        Err(_) => Probe::No,
    }
}

macro_rules! dump_extractor {
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

dump_extractor!(As400DesExtractor, As400Des);
dump_extractor!(As400Ssha1Extractor, As400Ssha1);
dump_extractor!(LotusNotesExtractor, LotusNotes);
dump_extractor!(OpenvmsExtractor, Openvms);
dump_extractor!(Oracle11Extractor, Oracle11);
dump_extractor!(Oracle12cExtractor, Oracle12c);
dump_extractor!(OracleOtmExtractor, OracleOtm);
dump_extractor!(RacfKdfaesExtractor, RacfKdfaes);
dump_extractor!(RacfPassphraseExtractor, RacfPassphrase);
dump_extractor!(SybasePropExtractor, SybaseProp);
