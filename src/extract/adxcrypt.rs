//! IBM/Toshiba 4690 ADXCSOUF extraction.

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Adxcrypt;
use crate::{HashType, HashValue};

pub struct AdxcryptExtractor;

fn pairs(data: &[u8]) -> Vec<(String, String)> {
    let mut result = Vec::new();
    let mut index = 0;
    while index + 12 <= data.len() {
        if !data[index].is_ascii_alphanumeric() && !matches!(data[index], b'_' | b'-') {
            index += 1;
            continue;
        }
        let start = index;
        while index < data.len()
            && (data[index].is_ascii_alphanumeric() || matches!(data[index], b'_' | b'-'))
            && index - start < 9
        {
            index += 1;
        }
        if index - start < 3
            || index >= data.len()
            || data[index] != b' '
            || index + 9 > data.len()
            || !data[index + 1..index + 9].iter().all(u8::is_ascii_digit)
        {
            continue;
        }
        let user = std::str::from_utf8(&data[start..index]).expect("ASCII user");
        let hash = std::str::from_utf8(&data[index + 1..index + 9]).expect("ASCII hash");
        result.push((user.to_owned(), hash.to_owned()));
        index += 9;
    }
    result
}

impl Extractor for AdxcryptExtractor {
    fn slug(&self) -> &'static str {
        Adxcrypt::SLUG
    }

    fn exact(&self) -> bool {
        false
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match artifact.primary().read_all() {
            Ok(data) if !pairs(&data).is_empty() => {
                Probe::maybe("ADXCSOUF-style user records; use `--type adxcrypt`")
            }
            _ => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let data = artifact.primary().read_all().map_err(|error| {
            ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
        })?;
        let pairs = pairs(&data);
        if pairs.is_empty() {
            return Err(ExtractError::Unsupported(
                "no ADXCSOUF user records found".to_owned(),
            ));
        }
        Ok(pairs
            .into_iter()
            .map(|(_, hash)| Box::new(Adxcrypt { payload: hash }) as Box<dyn HashValue>)
            .collect())
    }
}
