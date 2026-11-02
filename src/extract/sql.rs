//! Password hashes embedded in SQL dumps and table exports.

use std::str;

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::{
    Mssql2000, Mssql2005, Mssql2012, Mssql2025, Mysql323, MysqlA, MysqlSha1, OracleH, OracleT,
    PostgresScramSha256,
};
use crate::{HashType, HashValue, Parse, ParseOptions};

fn tokens(artifact: &Artifact) -> Result<Vec<String>, ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    let text = str::from_utf8(&data)
        .map_err(|_| ExtractError::Invalid("SQL dump is not UTF-8".to_owned()))?;
    let mut tokens = Vec::new();
    let mut token = String::new();
    for character in text.chars() {
        if character.is_whitespace() || matches!(character, '\'' | '"' | ',' | '(' | ')' | ';') {
            if !token.is_empty() {
                tokens.push(std::mem::take(&mut token));
            }
        } else {
            token.push(character);
        }
    }
    if !token.is_empty() {
        tokens.push(token);
    }
    Ok(tokens)
}

fn extract<T>(artifact: &Artifact, prefix: Option<&str>) -> Result<Vec<T>, ExtractError>
where
    T: Parse + HashValue + 'static,
{
    let opts = ParseOptions::default();
    let mut hashes = Vec::new();
    for token in tokens(artifact)? {
        let candidate = prefix
            .and_then(|prefix| token.strip_prefix(prefix))
            .unwrap_or(&token);
        if let Ok(hash) = T::parse(candidate, &opts) {
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

fn probe<T>(artifact: &Artifact, prefix: Option<&str>) -> Probe
where
    T: Parse + HashValue + 'static,
{
    match extract::<T>(artifact, prefix) {
        Ok(_) => Probe::yes("SQL password hash value"),
        Err(_) => Probe::No,
    }
}

macro_rules! sql_extractor {
    ($name:ident, $ty:ty, $prefix:expr) => {
        pub struct $name;
        impl Extractor for $name {
            fn slug(&self) -> &'static str {
                <$ty>::SLUG
            }
            fn probe(&self, artifact: &Artifact) -> Probe {
                probe::<$ty>(artifact, $prefix)
            }
            fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
                Ok(extract::<$ty>(artifact, $prefix)?
                    .into_iter()
                    .map(|hash| Box::new(hash) as Box<dyn HashValue>)
                    .collect())
            }
        }
    };
}

sql_extractor!(Mysql323Extractor, Mysql323, None);
sql_extractor!(MysqlSha1Extractor, MysqlSha1, None);
sql_extractor!(MysqlAExtractor, MysqlA, None);
sql_extractor!(Mssql2000Extractor, Mssql2000, None);
sql_extractor!(Mssql2005Extractor, Mssql2005, None);
sql_extractor!(Mssql2012Extractor, Mssql2012, None);
sql_extractor!(Mssql2025Extractor, Mssql2025, None);
sql_extractor!(PostgresScramSha256Extractor, PostgresScramSha256, None);
sql_extractor!(OracleHExtractor, OracleH, Some("H:"));
sql_extractor!(OracleTExtractor, OracleT, Some("T:"));
