//! OpenSSH and PEM encrypted private key extraction.

use omniex::extract::{Artifact, ExtractError, Extracted, Extractor, Probe};
use omniex::types::Sshng;
use omniex::{HashType, HashValue};

const SSHNG_MAX_BYTES: u64 = 4 * 1024 * 1024;
const AUTH_MAGIC: &[u8] = b"openssh-key-v1\0";

struct PemBlock {
    label: String,
    headers: Vec<(String, String)>,
    body: String,
    offset: usize,
}

fn pem_blocks(text: &str) -> Result<Vec<PemBlock>, ExtractError> {
    let mut blocks = Vec::new();
    let mut search = 0;
    while let Some(begin) = text[search..].find("-----BEGIN ") {
        let begin = search + begin;
        let label_start = begin + "-----BEGIN ".len();
        let label_end = text[label_start..]
            .find("-----")
            .map(|offset| label_start + offset)
            .ok_or_else(|| ExtractError::Invalid("unterminated PEM header".to_owned()))?;
        let label = text[label_start..label_end].to_owned();
        let body_start = label_end + "-----".len();
        let end_marker = format!("-----END {label}-----");
        let end = text[body_start..]
            .find(&end_marker)
            .map(|offset| body_start + offset)
            .ok_or_else(|| ExtractError::Invalid("unterminated PEM block".to_owned()))?;

        let mut headers = Vec::new();
        let mut body = String::new();
        let mut in_headers = true;
        let content = text[body_start..end].trim_start_matches(['\r', '\n']);
        for line in content.lines() {
            let line = line.trim();
            if in_headers {
                if line.is_empty() {
                    in_headers = false;
                    continue;
                }
                if let Some((name, value)) = line.split_once(':') {
                    headers.push((name.trim().to_owned(), value.trim().to_owned()));
                    continue;
                }
                in_headers = false;
            }
            body.push_str(line);
        }
        blocks.push(PemBlock {
            label,
            headers,
            body,
            offset: begin,
        });
        search = end + end_marker.len();
    }
    Ok(blocks)
}

fn header<'a>(block: &'a PemBlock, name: &str) -> Option<&'a str> {
    block
        .headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn decode_body(block: &PemBlock) -> Result<Vec<u8>, ExtractError> {
    omniex::parse::decode_base64(&block.body, block.offset)
        .map_err(|error| ExtractError::Invalid(format!("invalid PEM base64: {error}")))
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn u32(&mut self) -> Result<u32, ExtractError> {
        let end = self
            .pos
            .checked_add(4)
            .filter(|end| *end <= self.data.len())
            .ok_or_else(|| ExtractError::Invalid("truncated OpenSSH key".to_owned()))?;
        let mut number = 0u32;
        for byte in &self.data[self.pos..end] {
            number = (number << 8) | u32::from(*byte);
        }
        self.pos = end;
        Ok(number)
    }

    fn bytes(&mut self, length: usize) -> Result<&'a [u8], ExtractError> {
        let end = self
            .pos
            .checked_add(length)
            .filter(|end| *end <= self.data.len())
            .ok_or_else(|| ExtractError::Invalid("truncated OpenSSH key".to_owned()))?;
        let bytes = &self.data[self.pos..end];
        self.pos = end;
        Ok(bytes)
    }

    fn string(&mut self) -> Result<&'a [u8], ExtractError> {
        let length = usize::try_from(self.u32()?)
            .map_err(|_| ExtractError::Invalid("OpenSSH string is too long".to_owned()))?;
        self.bytes(length)
    }
}

fn new_format(data: &[u8]) -> Result<Option<Sshng>, ExtractError> {
    if !data.starts_with(AUTH_MAGIC) {
        return Err(ExtractError::Invalid(
            "missing OpenSSH private key magic".to_owned(),
        ));
    }
    let mut cursor = Cursor::new(&data[AUTH_MAGIC.len()..]);
    let cipher_name = cursor.string()?;
    let kdf_name = cursor.string()?;
    let kdf_options = cursor.string()?;

    if cipher_name == b"none" || kdf_name == b"none" {
        return Ok(None);
    }

    let cipher = match cipher_name {
        b"aes256-ctr" => 6,
        b"aes256-cbc" => 2,
        other => {
            return Err(ExtractError::Unsupported(format!(
                "unsupported OpenSSH cipher {}",
                String::from_utf8_lossy(other)
            )));
        }
    };
    if kdf_name != b"bcrypt" {
        return Err(ExtractError::Unsupported(
            "unsupported OpenSSH key derivation function".to_owned(),
        ));
    }

    let mut kdf = Cursor::new(kdf_options);
    let salt = kdf.string()?;
    let rounds = kdf.u32()?;
    if salt.len() != 16 {
        return Err(ExtractError::Invalid(
            "OpenSSH bcrypt salt must be 16 bytes".to_owned(),
        ));
    }

    let keys = cursor.u32()?;
    for _ in 0..keys {
        cursor.string()?;
    }
    let private_length = usize::try_from(cursor.u32()?)
        .map_err(|_| ExtractError::Invalid("OpenSSH private blob is too long".to_owned()))?;
    let ciphertext_offset = AUTH_MAGIC
        .len()
        .checked_add(cursor.pos)
        .ok_or_else(|| ExtractError::Invalid("OpenSSH offset overflow".to_owned()))?;
    cursor.bytes(private_length)?;

    Ok(Some(Sshng {
        cipher,
        iv: salt.to_vec(),
        data: data.to_vec(),
        extra: format!("{rounds}${ciphertext_offset}"),
    }))
}

fn legacy_format(block: &PemBlock) -> Result<Option<Sshng>, ExtractError> {
    let procedure = header(block, "Proc-Type").unwrap_or_default();
    if !procedure.contains("ENCRYPTED") {
        return Ok(None);
    }
    let dek_info = header(block, "DEK-Info")
        .ok_or_else(|| ExtractError::Invalid("missing PEM DEK-Info header".to_owned()))?;
    let (encryption, iv) = dek_info
        .split_once(',')
        .ok_or_else(|| ExtractError::Invalid("invalid PEM DEK-Info header".to_owned()))?;
    let iv = omniex::parse::decode_hex(iv.trim(), 0)
        .map_err(|error| ExtractError::Invalid(format!("invalid PEM IV: {error}")))?;

    let cipher = match encryption.trim().to_ascii_uppercase().as_str() {
        "DES-EDE3-CBC" => 0,
        "AES-128-CBC" => {
            if block.label.starts_with("EC ") {
                3
            } else {
                1
            }
        }
        "AES-192-CBC" => 4,
        "AES-256-CBC" => 5,
        "DES-CBC" => 6,
        other => {
            return Err(ExtractError::Unsupported(format!(
                "unsupported PEM cipher {other}"
            )));
        }
    };

    let data = decode_body(block)?;
    if data.is_empty() {
        return Err(ExtractError::Invalid("empty PEM private key".to_owned()));
    }
    Ok(Some(Sshng {
        cipher,
        iv,
        data,
        extra: String::new(),
    }))
}

fn keys_from_artifact(artifact: &Artifact) -> Result<Vec<Sshng>, ExtractError> {
    if artifact.primary().len() > SSHNG_MAX_BYTES {
        return Err(ExtractError::Unsupported(format!(
            "{} is larger than the SSH key limit",
            artifact.label()
        )));
    }
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    let text = String::from_utf8_lossy(&data);
    let blocks = pem_blocks(&text)?;
    let mut keys = Vec::new();
    for block in &blocks {
        if block.label == "OPENSSH PRIVATE KEY" {
            if let Some(key) = new_format(&decode_body(block)?)? {
                keys.push(key);
            }
        } else if block.label.ends_with("PRIVATE KEY")
            && let Some(key) = legacy_format(block)?
        {
            keys.push(key);
        }
    }
    if keys.is_empty() {
        return Err(ExtractError::Unsupported(
            "no encrypted SSH or PEM private key found".to_owned(),
        ));
    }
    Ok(keys)
}

pub struct SshngExtractor;

impl Extractor for SshngExtractor {
    fn slug(&self) -> &'static str {
        Sshng::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match keys_from_artifact(artifact) {
            Ok(keys) if !keys.is_empty() => Probe::yes("encrypted SSH or PEM private key"),
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
