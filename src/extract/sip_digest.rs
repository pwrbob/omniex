//! SIP digest authentication extraction.
//!
//! Digest parameters are taken from `Authorization` and
//! `Proxy-Authorization` request headers, split into the hashcat `$sip$`
//! field layout.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::str;

use super::iscsi_chap::capture::{self, Protocol};
use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::SipDigest;
use crate::{HashType, HashValue};

const MAX_STREAM: usize = 1024 * 1024;

/// Extracts SIP digest authentication headers from a packet capture.
pub struct SipDigestExtractor;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Record {
    username: String,
    realm: String,
    method: String,
    uri_prefix: String,
    uri_resource: String,
    uri_suffix: String,
    nonce: String,
    nonce_client: String,
    nonce_count: String,
    qop: String,
    digest: [u8; 16],
}

#[derive(Default)]
struct Parsed {
    sip: bool,
    unsupported: bool,
    records: Vec<Record>,
}

#[derive(Default)]
struct Direction {
    buffer: Vec<u8>,
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn decode_digest(text: &str) -> Option<[u8; 16]> {
    if text.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (index, pair) in text.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        out[index] = (hex_value(pair[0])? << 4) | hex_value(pair[1])?;
    }
    Some(out)
}

fn parameters(input: &str) -> Vec<(String, String)> {
    let mut result = Vec::new();
    let mut rest = input;
    loop {
        rest = rest
            .trim_start_matches(|character: char| character == ',' || character.is_whitespace());
        if rest.is_empty() {
            break;
        }
        let Some(equals) = rest.find('=') else {
            break;
        };
        let name = &rest[..equals];
        if let Some(comma) = name.find(',') {
            rest = &name[comma + 1..];
            continue;
        }
        let key = name.trim().to_ascii_lowercase();
        let after = &rest[equals + 1..];
        let value;
        if let Some(quoted) = after.trim_start().strip_prefix('"') {
            let mut text = String::new();
            let mut escaped = false;
            let mut end = None;
            for (index, character) in quoted.char_indices() {
                if escaped {
                    text.push(character);
                    escaped = false;
                } else if character == '\\' {
                    escaped = true;
                } else if character == '"' {
                    end = Some(index + 1);
                    break;
                } else {
                    text.push(character);
                }
            }
            let Some(end) = end else {
                break;
            };
            value = text;
            rest = &quoted[end..];
        } else {
            let end = after.find(',').unwrap_or(after.len());
            value = after[..end].trim().to_owned();
            rest = &after[end..];
        }
        result.push((key, value));
    }
    result
}

fn split_uri(uri: &str) -> (String, String, String) {
    match uri.split_once(':') {
        Some((prefix, rest)) => match rest.rsplit_once(':') {
            Some((resource, suffix)) => (prefix.to_owned(), resource.to_owned(), suffix.to_owned()),
            None => (prefix.to_owned(), rest.to_owned(), String::new()),
        },
        None => (String::new(), uri.to_owned(), String::new()),
    }
}

enum Digest {
    Record(Box<Record>),
    Unsupported,
}

fn digest_record(method: &str, value: &str) -> Option<Digest> {
    let value = value.trim();
    let rest = value
        .get(..6)
        .filter(|prefix| prefix.eq_ignore_ascii_case("digest"))?;
    let fields = parameters(value.get(rest.len()..)?.trim_start_matches(','));
    let get = |name: &str| {
        fields
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    };

    if let Some(algorithm) = get("algorithm")
        && !algorithm.eq_ignore_ascii_case("MD5")
    {
        return Some(Digest::Unsupported);
    }
    let qop = get("qop").unwrap_or("");
    if !qop.is_empty() && !qop.eq_ignore_ascii_case("auth") && !qop.eq_ignore_ascii_case("auth-int")
    {
        return Some(Digest::Unsupported);
    }
    let response = get("response")?;
    let username = get("username")?;
    let realm = get("realm")?;
    let nonce = get("nonce")?;
    let uri = get("uri")?;
    let digest = decode_digest(response)?;
    if username.is_empty() || realm.is_empty() || nonce.is_empty() || uri.is_empty() {
        return None;
    }
    let (uri_prefix, uri_resource, uri_suffix) = split_uri(uri);
    if uri_resource.is_empty() {
        return None;
    }
    let nonce_count = get("nc").unwrap_or("");
    let nonce_client = get("cnonce").unwrap_or("");
    if !qop.is_empty() && (nonce_count.is_empty() || nonce_client.is_empty()) {
        return None;
    }
    Some(Digest::Record(Box::new(Record {
        username: username.to_owned(),
        realm: realm.to_owned(),
        method: method.to_owned(),
        uri_prefix,
        uri_resource,
        uri_suffix,
        nonce: nonce.to_owned(),
        nonce_client: nonce_client.to_owned(),
        nonce_count: nonce_count.to_owned(),
        qop: qop.to_owned(),
        digest,
    })))
}

fn header_lines(head: &str) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    for line in head.split("\r\n") {
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some(last) = lines.last_mut() {
                last.push(' ');
                last.push_str(line.trim());
            }
        } else {
            lines.push(line.to_owned());
        }
    }
    lines
}

fn parse_message(data: &[u8], parsed: &mut Parsed) {
    let Ok(text) = str::from_utf8(data) else {
        return;
    };
    let text = text.split('\0').next().unwrap_or_default();
    let Some(end) = text.find("\r\n\r\n") else {
        return;
    };
    let mut lines = header_lines(&text[..end]).into_iter();
    let Some(request) = lines.next() else {
        return;
    };
    let mut parts = request.split(' ');
    let (Some(method), Some(_uri), Some(version)) = (parts.next(), parts.next(), parts.next())
    else {
        return;
    };
    if version != "SIP/2.0" || parts.next().is_some() {
        return;
    }
    if method.is_empty()
        || !method
            .chars()
            .all(|character| character.is_ascii_uppercase() || character == '_')
    {
        return;
    }
    parsed.sip = true;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if !name.eq_ignore_ascii_case("Authorization")
            && !name.eq_ignore_ascii_case("Proxy-Authorization")
        {
            continue;
        }
        match digest_record(method, value) {
            Some(Digest::Record(record)) => parsed.records.push(*record),
            Some(Digest::Unsupported) => parsed.unsupported = true,
            None => {}
        }
    }
}

fn content_length(head: &str) -> usize {
    header_lines(head)
        .into_iter()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("Content-Length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0)
}

fn drain_stream(buffer: &mut Vec<u8>, parsed: &mut Parsed) {
    while let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
        let head = match str::from_utf8(&buffer[..position]) {
            Ok(head) => head.to_owned(),
            Err(_) => {
                buffer.clear();
                return;
            }
        };
        let total = position + 4 + content_length(&head);
        if buffer.len() < total {
            break;
        }
        let message = buffer[..total].to_vec();
        parse_message(&message, parsed);
        buffer.drain(..total);
    }
}

fn scan(artifact: &Artifact) -> Result<Parsed, ExtractError> {
    let source = artifact.primary();
    if !capture::is_capture(source) {
        return Err(ExtractError::Unsupported(
            "not a SIP packet capture".to_owned(),
        ));
    }
    let mut parsed = Parsed::default();
    let mut streams: BTreeMap<(SocketAddr, SocketAddr), Direction> = BTreeMap::new();
    capture::scan_datagrams(source, |datagram| match datagram.protocol {
        Protocol::Udp => parse_message(datagram.payload, &mut parsed),
        Protocol::Tcp => {
            let direction = streams
                .entry((datagram.source, datagram.destination))
                .or_default();
            direction.buffer.extend_from_slice(datagram.payload);
            drain_stream(&mut direction.buffer, &mut parsed);
            if direction.buffer.len() > MAX_STREAM {
                direction.buffer.clear();
            }
        }
    })?;
    Ok(parsed)
}

impl Extractor for SipDigestExtractor {
    fn slug(&self) -> &'static str {
        SipDigest::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match scan(artifact) {
            Ok(parsed) if !parsed.records.is_empty() => {
                Probe::yes("SIP digest MD5 Authorization header")
            }
            Ok(parsed) if parsed.unsupported => Probe::Maybe(
                "SIP digest authentication with an unsupported algorithm or qop".to_owned(),
            ),
            Ok(parsed) if parsed.sip => {
                Probe::Maybe("SIP message without digest authentication".to_owned())
            }
            Ok(_) => Probe::No,
            Err(ExtractError::Unsupported(_)) => Probe::No,
            Err(ExtractError::Invalid(reason)) => Probe::maybe(reason),
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let parsed = scan(artifact)?;
        if parsed.records.is_empty() {
            return Err(ExtractError::Unsupported(
                "no SIP digest authentication headers".to_owned(),
            ));
        }
        let unique: BTreeSet<Record> = parsed.records.into_iter().collect();
        Ok(unique
            .into_iter()
            .map(|record| {
                Box::new(SipDigest {
                    unused1: String::new(),
                    unused2: String::new(),
                    username: record.username,
                    realm: record.realm,
                    method: record.method,
                    uri_prefix: record.uri_prefix,
                    uri_resource: record.uri_resource,
                    uri_suffix: record.uri_suffix,
                    nonce: record.nonce,
                    nonce_client: record.nonce_client,
                    nonce_count: record.nonce_count,
                    qop: record.qop,
                    directive: "MD5".to_owned(),
                    digest: record.digest,
                }) as Box<dyn HashValue>
            })
            .collect())
    }
}
