//! PuTTY private key extraction.

use omniex::extract::{Artifact, ExtractError, Extracted, Extractor, Probe};
use omniex::types::Putty;
use omniex::{HashType, HashValue};

const PUTTY_MAX_BYTES: u64 = 4 * 1024 * 1024;
const HEADER_V1: &str = "PuTTY-User-Key-File-1:";
const HEADER_V2: &str = "PuTTY-User-Key-File-2:";

fn field<'a>(fields: &'a [(String, String)], name: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

/// Reads one key starting at `start`, returning the key and the next offset.
fn parse_key(lines: &[&str], start: usize) -> Result<(Option<Putty>, usize), ExtractError> {
    let first = lines[start];
    let (old_format, algorithm) = if let Some(value) = first.strip_prefix(HEADER_V1) {
        (true, value.trim().to_owned())
    } else if let Some(value) = first.strip_prefix(HEADER_V2) {
        (false, value.trim().to_owned())
    } else {
        return Err(ExtractError::Unsupported(
            "not a PuTTY private key".to_owned(),
        ));
    };
    if algorithm.is_empty() {
        return Err(ExtractError::Invalid(
            "missing PuTTY key algorithm".to_owned(),
        ));
    }

    let mut cursor = start + 1;
    let mut fields = Vec::new();
    while cursor < lines.len() {
        let line = lines[cursor];
        let Some((name, value)) = line.split_once(':') else {
            break;
        };
        fields.push((name.trim().to_owned(), value.trim().to_owned()));
        cursor += 1;
        if name.trim().eq_ignore_ascii_case("Public-Lines") {
            break;
        }
    }

    let encryption = field(&fields, "Encryption")
        .ok_or_else(|| ExtractError::Invalid("missing PuTTY Encryption header".to_owned()))?
        .to_owned();
    let comment = field(&fields, "Comment").unwrap_or_default().to_owned();
    let public_lines = parse_lines(field(&fields, "Public-Lines"), "Public-Lines")?;

    let public_blob = read_blob(lines, &mut cursor, public_lines)?;

    let mut private_fields = Vec::new();
    while cursor < lines.len() {
        let line = lines[cursor];
        let Some((name, value)) = line.split_once(':') else {
            break;
        };
        private_fields.push((name.trim().to_owned(), value.trim().to_owned()));
        cursor += 1;
        if name.trim().eq_ignore_ascii_case("Private-Lines") {
            break;
        }
    }
    let private_lines = parse_lines(field(&private_fields, "Private-Lines"), "Private-Lines")?;
    let private_blob = read_blob(lines, &mut cursor, private_lines)?;

    let (is_mac, mac) = if cursor < lines.len() {
        let line = lines[cursor];
        if let Some(value) = line.strip_prefix("Private-MAC:") {
            cursor += 1;
            (true, value.trim().to_owned())
        } else if let Some(value) = line.strip_prefix("Private-Hash:") {
            cursor += 1;
            (false, value.trim().to_owned())
        } else {
            return Err(ExtractError::Invalid(
                "missing PuTTY private key MAC".to_owned(),
            ));
        }
    } else {
        return Err(ExtractError::Invalid(
            "missing PuTTY private key MAC".to_owned(),
        ));
    };
    if mac.is_empty() {
        return Err(ExtractError::Invalid(
            "empty PuTTY private key MAC".to_owned(),
        ));
    }

    let (cipher, block) = match encryption.as_str() {
        "aes256-cbc" => (1, 16),
        "none" => (0, 1),
        other => {
            return Err(ExtractError::Unsupported(format!(
                "unsupported PuTTY encryption {other}"
            )));
        }
    };

    if cipher == 0 {
        return Ok((None, cursor));
    }

    let mut value = format!(
        "{cipher}*{block}*{}*{}*{mac}*{}*{}*{}*{}",
        u8::from(is_mac),
        u8::from(old_format),
        public_blob.len(),
        omniex::format::hex(&public_blob),
        private_blob.len(),
        omniex::format::hex(&private_blob)
    );
    if !old_format {
        value.push('*');
        value.push_str(&algorithm);
        value.push('*');
        value.push_str(&encryption);
        value.push('*');
        value.push_str(&comment);
    }

    Ok((Some(Putty { fields: value }), cursor))
}

fn parse_lines(value: Option<&str>, name: &str) -> Result<usize, ExtractError> {
    let value = value.ok_or_else(|| ExtractError::Invalid(format!("missing PuTTY {name}")))?;
    value
        .parse::<usize>()
        .map_err(|_| ExtractError::Invalid(format!("invalid PuTTY {name}")))
}

fn read_blob(lines: &[&str], cursor: &mut usize, count: usize) -> Result<Vec<u8>, ExtractError> {
    let mut body = String::new();
    for _ in 0..count {
        let line = lines
            .get(*cursor)
            .ok_or_else(|| ExtractError::Invalid("truncated PuTTY blob".to_owned()))?;
        body.push_str(line.trim());
        *cursor += 1;
    }
    omniex::parse::decode_base64(&body, 0)
        .map_err(|error| ExtractError::Invalid(format!("invalid PuTTY base64: {error}")))
}

fn keys_from_artifact(artifact: &Artifact) -> Result<Vec<Putty>, ExtractError> {
    if artifact.primary().len() > PUTTY_MAX_BYTES {
        return Err(ExtractError::Unsupported(format!(
            "{} is larger than the PuTTY key limit",
            artifact.label()
        )));
    }
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    let text = String::from_utf8_lossy(&data);
    let lines: Vec<&str> = text.lines().map(str::trim).collect();

    let mut keys = Vec::new();
    let mut cursor = 0;
    while cursor < lines.len() {
        let line = lines[cursor];
        if line.starts_with(HEADER_V1) || line.starts_with(HEADER_V2) {
            let (key, next) = parse_key(&lines, cursor)?;
            if let Some(key) = key {
                keys.push(key);
            }
            cursor = next;
        } else {
            cursor += 1;
        }
    }
    if keys.is_empty() {
        return Err(ExtractError::Unsupported(
            "no PuTTY private key found".to_owned(),
        ));
    }
    Ok(keys)
}

pub struct PuttyExtractor;

impl Extractor for PuttyExtractor {
    fn slug(&self) -> &'static str {
        Putty::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match keys_from_artifact(artifact) {
            Ok(keys) if !keys.is_empty() => Probe::yes("PuTTY private key header"),
            _ => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let keys = keys_from_artifact(artifact)?;
        Ok(keys
            .into_iter()
            .map(|key| Box::new(key) as Box<dyn HashValue>)
            .collect())
    }
}
