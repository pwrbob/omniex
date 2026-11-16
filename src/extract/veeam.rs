//! Veeam VBK backup metadata.

use super::{Artifact, ExtractError, Extracted, Extractor, Probe, ReadAt};
use crate::types::Veeam;
use crate::{HashType, HashValue};

const SIGNATURE: &[u8] = &[
    0x60, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
];
const PREFIX: usize = 96;
const DIGEST: usize = 16;
const DATA: usize = 64;
const RECORD: usize = SIGNATURE.len() + PREFIX + DIGEST + DATA;
const PROBE_WINDOW: u64 = 1 << 20;
const CHUNK: usize = 1 << 20;
const OVERLAP: usize = 256;
const ITERATIONS: u32 = 10_000;

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn offsets(source: &dyn ReadAt, window: u64) -> Result<Vec<u64>, ExtractError> {
    let total = source.len().min(window);
    let mut found = Vec::new();
    let mut carry: Vec<u8> = Vec::new();
    let mut offset = 0u64;

    while offset < total {
        let len = usize::try_from((total - offset).min(CHUNK as u64))
            .map_err(|_| ExtractError::Invalid("Veeam backup is too large".to_owned()))?;
        let mut chunk = vec![0; len];
        source
            .read_exact_at(offset, &mut chunk)
            .map_err(|error| ExtractError::Invalid(format!("cannot read Veeam backup: {error}")))?;

        let base = offset - carry.len() as u64;
        let mut buffer = std::mem::take(&mut carry);
        buffer.extend_from_slice(&chunk);

        let mut index = 0;
        while let Some(position) = find(&buffer[index..], SIGNATURE) {
            let absolute = base + (index + position) as u64;
            if found.last() != Some(&absolute) {
                found.push(absolute);
            }
            index += position + SIGNATURE.len();
        }

        let keep = buffer.len().min(OVERLAP);
        carry = buffer[buffer.len() - keep..].to_vec();
        offset += len as u64;
    }

    Ok(found)
}

fn extract(artifact: &Artifact) -> Result<Vec<Veeam>, ExtractError> {
    let source = artifact.primary();
    let mut hashes = Vec::new();
    for offset in offsets(source, u64::MAX)? {
        let mut record = [0u8; RECORD];
        source
            .read_exact_at(offset, &mut record)
            .map_err(|_| ExtractError::Invalid("truncated Veeam VBK backup block".to_owned()))?;
        let digest_start = SIGNATURE.len() + PREFIX;
        let data_start = digest_start + DIGEST;
        let mut digest = [0u8; DIGEST];
        digest.copy_from_slice(&record[digest_start..data_start]);
        hashes.push(Veeam {
            data: crate::format::hex(&record[data_start..]),
            iterations: ITERATIONS,
            digest,
        });
    }
    if hashes.is_empty() {
        return Err(ExtractError::Unsupported(
            "no Veeam VBK backup blocks found".to_owned(),
        ));
    }
    Ok(hashes)
}

/// Extractor for Veeam VBK backup metadata.
pub struct VeeamExtractor;

impl Extractor for VeeamExtractor {
    fn slug(&self) -> &'static str {
        Veeam::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match offsets(artifact.primary(), PROBE_WINDOW) {
            Ok(found) if !found.is_empty() => Probe::yes("Veeam VBK backup block"),
            _ => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(extract(artifact)?
            .into_iter()
            .map(|hash| Box::new(hash) as Box<dyn HashValue>)
            .collect())
    }
}
