//! Clipperz offline export extraction.

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Clipperz;
use crate::{HashType, HashValue};

const MARKER: &str = "_clipperz_dump_data_";
const MAX_EXPORT: u64 = 64 << 20;

pub struct ClipperzExtractor;

enum Node {
    Text(String),
    Object(Vec<(String, Node)>),
}

struct Parser<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> Parser<'a> {
    fn new(data: &'a [u8], position: usize) -> Self {
        Self { data, position }
    }

    fn peek(&self) -> Option<u8> {
        self.data.get(self.position).copied()
    }

    fn skip_space(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            self.position += 1;
        }
    }

    fn expect(&mut self, byte: u8) -> Option<()> {
        self.skip_space();
        if self.peek() != Some(byte) {
            return None;
        }
        self.position += 1;
        Some(())
    }

    fn string(&mut self) -> Option<String> {
        let quote = self.peek()?;
        if quote != b'\'' && quote != b'"' {
            return None;
        }
        self.position += 1;
        let mut text = Vec::new();
        while let Some(byte) = self.peek() {
            self.position += 1;
            if byte == quote {
                return Some(String::from_utf8_lossy(&text).into_owned());
            }
            if byte == b'\\' {
                let escaped = self.peek()?;
                self.position += 1;
                text.push(escaped);
            } else {
                text.push(byte);
            }
        }
        None
    }

    fn bare(&mut self) -> Option<String> {
        let start = self.position;
        while let Some(byte) = self.peek() {
            if matches!(
                byte,
                b' ' | b'\t'
                    | b'\r'
                    | b'\n'
                    | b','
                    | b':'
                    | b'{'
                    | b'}'
                    | b'['
                    | b']'
                    | b'\''
                    | b'"'
            ) {
                break;
            }
            self.position += 1;
        }
        if self.position == start {
            return None;
        }
        Some(String::from_utf8_lossy(&self.data[start..self.position]).into_owned())
    }

    fn value(&mut self) -> Option<Node> {
        self.skip_space();
        match self.peek()? {
            b'{' => self.object(),
            b'\'' | b'"' => self.string().map(Node::Text),
            _ => self.bare().map(Node::Text),
        }
    }

    fn object(&mut self) -> Option<Node> {
        self.expect(b'{')?;
        let mut entries = Vec::new();
        loop {
            self.skip_space();
            if self.peek()? == b'}' {
                self.position += 1;
                return Some(Node::Object(entries));
            }
            let key = match self.peek()? {
                b'\'' | b'"' => self.string()?,
                _ => self.bare()?,
            };
            self.expect(b':')?;
            let value = self.value()?;
            entries.push((key, value));
            self.skip_space();
            match self.peek()? {
                b',' => {
                    self.position += 1;
                }
                b'}' => {}
                _ => return None,
            }
        }
    }
}

fn text<'a>(entries: &'a [(String, Node)], key: &str) -> Option<&'a str> {
    entries.iter().find_map(|(name, node)| {
        if name == key {
            match node {
                Node::Text(value) => Some(value.as_str()),
                Node::Object(_) => None,
            }
        } else {
            None
        }
    })
}

fn object<'a>(entries: &'a [(String, Node)], key: &str) -> Option<&'a [(String, Node)]> {
    entries.iter().find_map(|(name, node)| {
        if name == key {
            match node {
                Node::Object(inner) => Some(inner.as_slice()),
                Node::Text(_) => None,
            }
        } else {
            None
        }
    })
}

fn export(artifact: &Artifact) -> Result<Vec<Clipperz>, ExtractError> {
    let source = artifact.primary();
    if source.len() > MAX_EXPORT {
        return Err(ExtractError::Unsupported(
            "Clipperz export is too large".to_owned(),
        ));
    }
    let data = source.read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    let text = String::from_utf8_lossy(&data);
    let marker = text
        .find(MARKER)
        .ok_or_else(|| ExtractError::Unsupported("missing Clipperz export marker".to_owned()))?;
    let open = text[marker..]
        .find('{')
        .ok_or_else(|| ExtractError::Invalid("Clipperz export has no data object".to_owned()))?
        + marker;
    let mut parser = Parser::new(text.as_bytes(), open);
    let Node::Object(root) = parser
        .object()
        .ok_or_else(|| ExtractError::Invalid("invalid Clipperz export object".to_owned()))?
    else {
        return Err(ExtractError::Invalid(
            "invalid Clipperz export object".to_owned(),
        ));
    };
    let users = object_strict(&root, "users")?;

    let mut hashes = Vec::new();
    for (name, node) in users {
        if name == "catchAllUser" {
            continue;
        }
        let Node::Object(fields) = node else {
            continue;
        };
        let Some(salt) = text_of(fields, "s") else {
            continue;
        };
        let Some(verifier) = text_of(fields, "v") else {
            continue;
        };
        hashes.push(Clipperz {
            digest: verifier.to_owned(),
            salt: salt.to_owned(),
            email: name.clone(),
        });
    }

    if hashes.is_empty() {
        return Err(ExtractError::Invalid(
            "Clipperz export has no user verifier".to_owned(),
        ));
    }
    Ok(hashes)
}

fn object_strict<'a>(
    entries: &'a [(String, Node)],
    key: &str,
) -> Result<&'a [(String, Node)], ExtractError> {
    object(entries, key)
        .ok_or_else(|| ExtractError::Invalid(format!("missing Clipperz `{key}` object")))
}

fn text_of<'a>(entries: &'a [(String, Node)], key: &str) -> Option<&'a str> {
    text(entries, key)
}

impl Extractor for ClipperzExtractor {
    fn slug(&self) -> &'static str {
        Clipperz::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match export(artifact) {
            Ok(_) => Probe::yes("Clipperz offline export"),
            Err(ExtractError::Invalid(reason)) => Probe::maybe(reason),
            Err(ExtractError::Unsupported(_)) => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(export(artifact)?
            .into_iter()
            .map(|value| Box::new(value) as Box<dyn HashValue>)
            .collect())
    }
}
