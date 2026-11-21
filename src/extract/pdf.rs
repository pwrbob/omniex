//! PDF Standard security handler extraction.

use std::collections::HashSet;

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Pdf;
use crate::{HashType, HashValue};

pub struct PdfExtractor;

const ENCRYPTION_DICTIONARY_KEYS: [&[u8]; 4] = [b"V", b"R", b"O", b"U"];

#[derive(Debug)]
enum Value {
    Name(Vec<u8>),
    Bytes(Vec<u8>),
    Integer(i64),
    Boolean(bool),
    Array(Vec<Value>),
    Dictionary(Vec<(Vec<u8>, Value)>),
    Reference,
}

impl Value {
    fn name(&self) -> Option<&[u8]> {
        match self {
            Self::Name(name) => Some(name),
            _ => None,
        }
    }

    fn bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(bytes) => Some(bytes),
            _ => None,
        }
    }

    fn integer(&self) -> Option<i64> {
        match self {
            Self::Integer(value) => Some(*value),
            _ => None,
        }
    }

    fn boolean(&self) -> Option<bool> {
        match self {
            Self::Boolean(value) => Some(*value),
            _ => None,
        }
    }
}

struct Parser<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(data: &'a [u8], pos: usize) -> Self {
        Self { data, pos }
    }

    fn peek(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    fn skip_whitespace(&mut self) {
        loop {
            while self.peek().is_some_and(is_whitespace) {
                self.pos += 1;
            }
            if self.peek() != Some(b'%') {
                break;
            }
            while self
                .peek()
                .is_some_and(|byte| byte != b'\n' && byte != b'\r')
            {
                self.pos += 1;
            }
        }
    }

    fn parse_value(&mut self, depth: usize) -> Result<Value, ExtractError> {
        if depth > 32 {
            return Err(ExtractError::Invalid(
                "PDF object nesting is too deep".to_owned(),
            ));
        }
        self.skip_whitespace();
        match self.peek() {
            Some(b'<') if self.data.get(self.pos + 1) == Some(&b'<') => {
                self.parse_dictionary(depth)
            }
            Some(b'<') => self.parse_hex_string(),
            Some(b'[') => self.parse_array(depth),
            Some(b'(') => self.parse_literal_string(),
            Some(b'/') => self.parse_name(),
            Some(b't') if self.data[self.pos..].starts_with(b"true") => {
                self.pos += 4;
                Ok(Value::Boolean(true))
            }
            Some(b'f') if self.data[self.pos..].starts_with(b"false") => {
                self.pos += 5;
                Ok(Value::Boolean(false))
            }
            Some(b'n') if self.data[self.pos..].starts_with(b"null") => {
                self.pos += 4;
                Ok(Value::Reference)
            }
            Some(b'+') | Some(b'-') | Some(b'0'..=b'9') => self.parse_number_or_reference(),
            Some(_) => Err(ExtractError::Invalid("unsupported PDF token".to_owned())),
            None => Err(ExtractError::Invalid("unexpected end of PDF".to_owned())),
        }
    }

    fn parse_number_or_reference(&mut self) -> Result<Value, ExtractError> {
        let value = self.parse_integer()?;
        let after_value = self.pos;

        self.skip_whitespace();
        if self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
            let _ = self.parse_integer()?;
            self.skip_whitespace();
            if self.peek() == Some(b'R') {
                self.pos += 1;
                return Ok(Value::Reference);
            }
        }
        self.pos = after_value;
        Ok(Value::Integer(value))
    }

    fn parse_integer(&mut self) -> Result<i64, ExtractError> {
        self.skip_whitespace();
        let start = self.pos;
        if matches!(self.peek(), Some(b'+') | Some(b'-')) {
            self.pos += 1;
        }
        let digits = self.pos;
        while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
            self.pos += 1;
        }
        if self.pos == digits {
            return Err(ExtractError::Invalid("expected a PDF integer".to_owned()));
        }
        let text = std::str::from_utf8(&self.data[start..self.pos])
            .map_err(|_| ExtractError::Invalid("invalid PDF integer".to_owned()))?;
        text.parse::<i64>()
            .map_err(|_| ExtractError::Invalid("PDF integer is out of range".to_owned()))
    }

    fn parse_name(&mut self) -> Result<Value, ExtractError> {
        if self.peek() != Some(b'/') {
            return Err(ExtractError::Invalid("expected a PDF name".to_owned()));
        }
        self.pos += 1;
        let start = self.pos;
        while self.peek().is_some_and(|byte| !is_delimiter(byte)) {
            self.pos += 1;
        }
        Ok(Value::Name(self.data[start..self.pos].to_vec()))
    }

    fn parse_literal_string(&mut self) -> Result<Value, ExtractError> {
        if self.peek() != Some(b'(') {
            return Err(ExtractError::Invalid(
                "expected a PDF literal string".to_owned(),
            ));
        }
        self.pos += 1;
        let mut depth = 1;
        let mut out = Vec::new();
        while let Some(byte) = self.peek() {
            self.pos += 1;
            match byte {
                b'(' => {
                    depth += 1;
                    out.push(byte);
                }
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        return Ok(Value::Bytes(out));
                    }
                    out.push(byte);
                }
                b'\\' => self.parse_escape(&mut out)?,
                _ => out.push(byte),
            }
        }
        Err(ExtractError::Invalid(
            "unterminated PDF literal string".to_owned(),
        ))
    }

    fn parse_escape(&mut self, out: &mut Vec<u8>) -> Result<(), ExtractError> {
        let Some(byte) = self.peek() else {
            return Err(ExtractError::Invalid(
                "unterminated PDF string escape".to_owned(),
            ));
        };
        self.pos += 1;
        match byte {
            b'n' => out.push(b'\n'),
            b'r' => out.push(b'\r'),
            b't' => out.push(b'\t'),
            b'b' => out.push(0x08),
            b'f' => out.push(0x0c),
            b'(' | b')' | b'\\' => out.push(byte),
            b'\r' => {
                if self.peek() == Some(b'\n') {
                    self.pos += 1;
                }
            }
            b'\n' => {}
            b'0'..=b'7' => {
                let mut value = u16::from(byte - b'0');
                for _ in 0..2 {
                    match self.peek() {
                        Some(digit @ b'0'..=b'7') => {
                            value = value * 8 + u16::from(digit - b'0');
                            self.pos += 1;
                        }
                        _ => break,
                    }
                }
                out.push((value & 0xff) as u8);
            }
            other => out.push(other),
        }
        Ok(())
    }

    fn parse_hex_string(&mut self) -> Result<Value, ExtractError> {
        if self.peek() != Some(b'<') {
            return Err(ExtractError::Invalid(
                "expected a PDF hexadecimal string".to_owned(),
            ));
        }
        self.pos += 1;
        let mut nibbles = Vec::new();
        while let Some(byte) = self.peek() {
            self.pos += 1;
            match byte {
                b'>' => {
                    if nibbles.len() % 2 != 0 {
                        nibbles.push(0);
                    }
                    let bytes = nibbles
                        .chunks_exact(2)
                        .map(|pair| (pair[0] << 4) | pair[1])
                        .collect();
                    return Ok(Value::Bytes(bytes));
                }
                byte if byte.is_ascii_whitespace() => {}
                byte => {
                    let nibble = hex_nibble(byte).ok_or_else(|| {
                        ExtractError::Invalid("invalid PDF hexadecimal string".to_owned())
                    })?;
                    nibbles.push(nibble);
                }
            }
        }
        Err(ExtractError::Invalid(
            "unterminated PDF hexadecimal string".to_owned(),
        ))
    }

    fn parse_array(&mut self, depth: usize) -> Result<Value, ExtractError> {
        self.pos += 1;
        let mut values = Vec::new();
        loop {
            self.skip_whitespace();
            match self.peek() {
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Value::Array(values));
                }
                Some(_) => values.push(self.parse_value(depth + 1)?),
                None => {
                    return Err(ExtractError::Invalid("unterminated PDF array".to_owned()));
                }
            }
        }
    }

    fn parse_dictionary(&mut self, depth: usize) -> Result<Value, ExtractError> {
        self.pos += 2;
        let mut entries = Vec::new();
        loop {
            self.skip_whitespace();
            match self.peek() {
                Some(b'>') if self.data.get(self.pos + 1) == Some(&b'>') => {
                    self.pos += 2;
                    return Ok(Value::Dictionary(entries));
                }
                Some(b'/') => {
                    let Value::Name(name) = self.parse_name()? else {
                        unreachable!();
                    };
                    let value = self.parse_value(depth + 1)?;
                    entries.push((name, value));
                }
                Some(_) => {
                    return Err(ExtractError::Invalid(
                        "invalid PDF dictionary entry".to_owned(),
                    ));
                }
                None => {
                    return Err(ExtractError::Invalid(
                        "unterminated PDF dictionary".to_owned(),
                    ));
                }
            }
        }
    }
}

fn is_whitespace(byte: u8) -> bool {
    matches!(byte, b'\0' | b'\t' | b'\n' | b'\x0c' | b'\r' | b' ')
}

fn is_delimiter(byte: u8) -> bool {
    is_whitespace(byte)
        || matches!(
            byte,
            b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
        )
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn dictionary_value<'a>(entries: &'a [(Vec<u8>, Value)], key: &[u8]) -> Option<&'a Value> {
    entries
        .iter()
        .find_map(|(name, value)| (name == key).then_some(value))
}

fn document_id(data: &[u8]) -> Option<Vec<u8>> {
    let mut found = None;
    let mut offset = 0;
    while offset + 3 <= data.len() {
        if &data[offset..offset + 3] == b"/ID"
            && data.get(offset + 3).is_none_or(|byte| is_delimiter(*byte))
        {
            let mut parser = Parser::new(data, offset + 3);
            if let Ok(Value::Array(values)) = parser.parse_value(0)
                && let Some(id) = values.first().and_then(Value::bytes)
            {
                found = Some(id.to_vec());
            }
        }
        offset += 1;
    }
    found
}

fn find_encryption_dictionaries(data: &[u8]) -> Vec<Vec<(Vec<u8>, Value)>> {
    let mut dictionaries = Vec::new();
    let mut offset = 0;
    while offset + 1 < data.len() {
        if data[offset] == b'<' && data[offset + 1] == b'<' {
            let mut parser = Parser::new(data, offset);
            if let Ok(Value::Dictionary(entries)) = parser.parse_value(0)
                && dictionary_value(&entries, b"Filter").and_then(Value::name) == Some(b"Standard")
            {
                dictionaries.push(entries);
            }
        }
        offset += 1;
    }
    dictionaries
}

fn required_integer(entries: &[(Vec<u8>, Value)], key: &[u8]) -> Result<i64, ExtractError> {
    dictionary_value(entries, key)
        .and_then(Value::integer)
        .ok_or_else(|| {
            ExtractError::Invalid(format!(
                "PDF encryption dictionary is missing /{}",
                String::from_utf8_lossy(key)
            ))
        })
}

fn required_bytes(entries: &[(Vec<u8>, Value)], key: &[u8]) -> Result<Vec<u8>, ExtractError> {
    dictionary_value(entries, key)
        .and_then(Value::bytes)
        .map(<[u8]>::to_vec)
        .ok_or_else(|| {
            ExtractError::Invalid(format!(
                "PDF encryption dictionary is missing /{}",
                String::from_utf8_lossy(key)
            ))
        })
}

fn convert_dictionary(entries: &[(Vec<u8>, Value)], id: &[u8]) -> Result<Pdf, ExtractError> {
    let version = required_integer(entries, b"V")?;
    let revision = required_integer(entries, b"R")?;
    if !matches!(
        (version, revision),
        (1, 2) | (2, 3) | (4, 4) | (5, 5) | (5, 6)
    ) {
        return Err(ExtractError::Unsupported(format!(
            "unsupported PDF encryption version V={version} R={revision}"
        )));
    }
    let key_length = dictionary_value(entries, b"Length")
        .and_then(Value::integer)
        .unwrap_or(40);
    if !(40..=256).contains(&key_length) {
        return Err(ExtractError::Invalid(format!(
            "invalid PDF key length {key_length}"
        )));
    }
    let permissions = required_integer(entries, b"P")?;
    let encrypt_metadata = dictionary_value(entries, b"EncryptMetadata")
        .and_then(Value::boolean)
        .unwrap_or(true);
    let owner = required_bytes(entries, b"O")?;
    let user = required_bytes(entries, b"U")?;
    if id.is_empty() || owner.is_empty() || user.is_empty() {
        return Err(ExtractError::Invalid(
            "PDF encryption dictionary has an empty value".to_owned(),
        ));
    }

    let mut data = format!(
        "{}*{}*{}*{}*{}",
        crate::format::hex(id),
        user.len(),
        crate::format::hex(&user),
        owner.len(),
        crate::format::hex(&owner)
    );

    if revision >= 5 {
        let user_encryption = required_bytes(entries, b"UE")?;
        let owner_encryption = required_bytes(entries, b"OE")?;
        if user_encryption.is_empty() || owner_encryption.is_empty() {
            return Err(ExtractError::Invalid(
                "PDF encryption dictionary has an empty key value".to_owned(),
            ));
        }
        data.push_str(&format!(
            "*{}*{}*{}*{}",
            user_encryption.len(),
            crate::format::hex(&user_encryption),
            owner_encryption.len(),
            crate::format::hex(&owner_encryption)
        ));
    }

    Ok(Pdf {
        version: u8::try_from(version)
            .map_err(|_| ExtractError::Invalid("invalid PDF version".to_owned()))?,
        revision: u8::try_from(revision)
            .map_err(|_| ExtractError::Invalid("invalid PDF revision".to_owned()))?,
        key_length: u32::try_from(key_length)
            .map_err(|_| ExtractError::Invalid("invalid PDF key length".to_owned()))?,
        permissions: crate::types::signed_permissions(permissions)
            .ok_or_else(|| ExtractError::Invalid(format!("invalid PDF permissions {permissions}")))?
            .to_string(),
        encrypt_metadata: u8::from(encrypt_metadata).to_string(),
        salt: id.len().to_string(),
        data,
        rc4_key: String::new(),
    })
}

fn parse(artifact: &Artifact) -> Result<Vec<Pdf>, ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    if !data[..data.len().min(1024)]
        .windows(5)
        .any(|window| window == b"%PDF-")
    {
        return Err(ExtractError::Unsupported("not a PDF document".to_owned()));
    }
    let dictionaries = find_encryption_dictionaries(&data);
    if dictionaries.is_empty() {
        return Err(ExtractError::Unsupported(
            "PDF has no Standard encryption dictionary".to_owned(),
        ));
    }
    let id = document_id(&data)
        .ok_or_else(|| ExtractError::Invalid("PDF trailer has no document ID".to_owned()))?;

    let mut seen = HashSet::new();
    let mut hashes = Vec::new();
    let mut first_error = None;
    for entries in &dictionaries {
        if !ENCRYPTION_DICTIONARY_KEYS
            .iter()
            .all(|key| dictionary_value(entries, key).is_some())
        {
            continue;
        }
        match convert_dictionary(entries, &id) {
            Ok(hash) => {
                let key = value_key(&hash);
                if seen.insert(key) {
                    hashes.push(hash);
                }
            }
            Err(ExtractError::Unsupported(reason)) => {
                first_error.get_or_insert(ExtractError::Unsupported(reason));
            }
            Err(ExtractError::Invalid(reason)) => {
                first_error.get_or_insert(ExtractError::Invalid(reason));
            }
        }
    }

    if hashes.is_empty() {
        return Err(first_error.unwrap_or_else(|| {
            ExtractError::Unsupported(
                "PDF Standard encryption dictionary lacks required fields".to_owned(),
            )
        }));
    }
    Ok(hashes)
}

fn value_key(hash: &Pdf) -> String {
    format!(
        "{}:{}:{}:{}:{}:{}:{}",
        hash.version,
        hash.revision,
        hash.key_length,
        hash.permissions,
        hash.encrypt_metadata,
        hash.salt,
        hash.data
    )
}

impl Extractor for PdfExtractor {
    fn slug(&self) -> &'static str {
        Pdf::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse(artifact) {
            Ok(hashes) if !hashes.is_empty() => Probe::yes("PDF Standard encryption dictionary"),
            Ok(_) => Probe::No,
            Err(ExtractError::Unsupported(reason))
                if reason == "not a PDF document"
                    || reason == "PDF has no Standard encryption dictionary" =>
            {
                Probe::No
            }
            Err(error) => Probe::maybe(error.to_string()),
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(parse(artifact)?
            .into_iter()
            .map(|hash| Box::new(hash) as Box<dyn HashValue>)
            .collect())
    }
}
