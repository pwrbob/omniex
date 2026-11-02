//! PGP Whole Disk Encryption user-record extraction.

use byteorder::{ByteOrder, LittleEndian};

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Pgpwde;
use crate::{HashType, HashValue};

pub struct PgpwdeExtractor;

const RECORD_SIZE: usize = 330;
const MAGIC: u32 = 1_464_101_120;

fn records(data: &[u8]) -> Vec<Pgpwde> {
    let mut hashes = Vec::new();
    for offset in 0..data.len().saturating_sub(RECORD_SIZE) {
        let record = &data[offset..offset + RECORD_SIZE];
        let size = LittleEndian::read_u16(&record[0..2]);
        let version = record[2];
        let kind = record[3];
        let magic = LittleEndian::read_u32(&record[4..8]);
        let current = record[9];
        if size != 512 || version != 0 || kind != 8 || magic != MAGIC || current != 0 {
            continue;
        }
        let algorithm = record[28];
        let s2k = record[162];
        let iterations = LittleEndian::read_u32(&record[163..167]);
        let salt = &record[170..186];
        let esk = &record[186..314]
            .iter()
            .take(128)
            .copied()
            .collect::<Vec<_>>();
        hashes.push(Pgpwde {
            fields: format!(
                "0*{}*{}*{}*{}*{}",
                algorithm,
                s2k,
                iterations,
                crate::format::hex(salt),
                crate::format::hex(esk)
            ),
        });
    }
    hashes
}

impl Extractor for PgpwdeExtractor {
    fn slug(&self) -> &'static str {
        Pgpwde::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        let data = match artifact.primary().read_all() {
            Ok(data) => data,
            Err(error) => return Probe::maybe(format!("cannot read artifact: {error}")),
        };
        if records(&data).is_empty() {
            Probe::No
        } else {
            Probe::yes("PGP WDE user record")
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let data = artifact.primary().read_all().map_err(|error| {
            ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
        })?;
        let hashes = records(&data);
        if hashes.is_empty() {
            return Err(ExtractError::Unsupported(
                "no PGP WDE user records found".to_owned(),
            ));
        }
        Ok(hashes
            .into_iter()
            .map(|hash| Box::new(hash) as Box<dyn HashValue>)
            .collect())
    }
}
