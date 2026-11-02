//! Windows Hello PIN and container records.

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::WindowsHello;
use crate::{HashType, HashValue, Parse, ParseOptions};

const PREFIX: &[u8] = b"$WINHELLO$";

fn terminator(byte: u8) -> bool {
    !byte.is_ascii_graphic()
        || matches!(
            byte,
            b'"' | b'\'' | b',' | b';' | b':' | b')' | b']' | b'}' | b'>' | b'|'
        )
}

fn take_ascii(data: &[u8], start: usize) -> Option<&str> {
    let mut end = start;
    while end < data.len() && !terminator(data[end]) {
        end += 1;
    }
    std::str::from_utf8(&data[start..end])
        .ok()
        .filter(|record| !record.is_empty())
}

fn take_utf16(data: &[u8], start: usize) -> Option<String> {
    let mut text = String::new();
    let mut index = start;
    while index + 1 < data.len() {
        let low = data[index];
        if data[index + 1] != 0 || terminator(low) {
            break;
        }
        text.push(low as char);
        index += 2;
    }
    (!text.is_empty()).then_some(text)
}

fn wide(prefix: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(prefix.len() * 2);
    for byte in prefix {
        out.push(*byte);
        out.push(0);
    }
    out
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn records(artifact: &Artifact) -> Result<Vec<String>, ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    let mut found = Vec::new();

    let mut index = 0;
    while let Some(position) = find(&data[index..], PREFIX) {
        let start = index + position;
        if let Some(record) = take_ascii(&data, start) {
            found.push(record.to_owned());
        }
        index = start + PREFIX.len();
    }

    let needle = wide(PREFIX);
    let mut index = 0;
    while let Some(position) = find(&data[index..], &needle) {
        let start = index + position;
        if let Some(record) = take_utf16(&data, start) {
            found.push(record);
        }
        index = start + needle.len();
    }

    Ok(found)
}

fn extract(artifact: &Artifact) -> Result<Vec<WindowsHello>, ExtractError> {
    let opts = ParseOptions::default();
    let mut hashes = Vec::new();
    for record in records(artifact)? {
        if let Ok(hash) = WindowsHello::parse(&record, &opts) {
            hashes.push(hash);
        }
    }
    if hashes.is_empty() {
        return Err(ExtractError::Unsupported(
            "no Windows Hello records found".to_owned(),
        ));
    }
    Ok(hashes)
}

/// Extractor for Windows Hello PIN and container records.
pub struct WindowsHelloExtractor;

impl Extractor for WindowsHelloExtractor {
    fn slug(&self) -> &'static str {
        WindowsHello::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match extract(artifact) {
            Ok(_) => Probe::yes("Windows Hello record"),
            Err(_) => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(extract(artifact)?
            .into_iter()
            .map(|hash| Box::new(hash) as Box<dyn HashValue>)
            .collect())
    }
}
