//! PKZIP hashes, rendered as a `$pkzip$` or `$pkzip2$` payload.

use std::sync::Arc;

use crate::extract::ReadAt;
use crate::parse;
use crate::{
    Encoding, FromFieldValue, HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render,
    RenderOptions,
};

/// Payload attached to a PKZIP hash.
///
/// Parsed hashes carry the complete payload. Extraction streams the final
/// record from the artifact when the embedded entry is too large to keep in
/// memory.
#[derive(Clone)]
pub enum PkzipPayload {
    /// Complete serialized payload.
    Owned(String),
    /// Payload whose trailing data record is read from the artifact.
    Streamed(StreamedPayload),
}

impl PkzipPayload {
    /// Serialized payload text, with the streamed data record omitted.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Owned(payload) => payload,
            Self::Streamed(streamed) => &streamed.head,
        }
    }

    /// Builds a payload that reads its data record from `source`.
    #[must_use]
    pub fn streamed(head: String, offset: u64, length: u64, source: Arc<dyn ReadAt>) -> Self {
        Self::Streamed(StreamedPayload {
            head,
            offset,
            length,
            source,
        })
    }
}

impl From<String> for PkzipPayload {
    fn from(payload: String) -> Self {
        Self::Owned(payload)
    }
}

impl AsRef<[u8]> for PkzipPayload {
    fn as_ref(&self) -> &[u8] {
        self.as_str().as_bytes()
    }
}

impl FromFieldValue for PkzipPayload {
    fn from_field_value(value: &str, encoding: Encoding) -> Result<Self, String> {
        String::from_field_value(value, encoding).map(Self::Owned)
    }
}

impl std::fmt::Debug for PkzipPayload {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Owned(payload) => formatter.debug_tuple("Owned").field(payload).finish(),
            Self::Streamed(streamed) => formatter
                .debug_struct("Streamed")
                .field("head", &streamed.head)
                .field("length", &streamed.length)
                .finish_non_exhaustive(),
        }
    }
}

impl PartialEq for PkzipPayload {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Owned(left), Self::Owned(right)) => left == right,
            (Self::Streamed(left), Self::Streamed(right)) => {
                left.head == right.head && left.length == right.length
            }
            _ => false,
        }
    }
}

impl Eq for PkzipPayload {}

impl std::hash::Hash for PkzipPayload {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self {
            Self::Owned(payload) => {
                0u8.hash(state);
                payload.hash(state);
            }
            Self::Streamed(streamed) => {
                1u8.hash(state);
                streamed.head.hash(state);
                streamed.length.hash(state);
            }
        }
    }
}

/// A `$pkzip$` payload whose trailing data record is read on demand.
#[derive(Clone)]
pub struct StreamedPayload {
    head: String,
    offset: u64,
    length: u64,
    source: Arc<dyn ReadAt>,
}

impl StreamedPayload {
    /// Number of bytes that will be hex-encoded after `head`.
    #[must_use]
    pub fn length(&self) -> u64 {
        self.length
    }

    fn write_hex(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        const CHUNK: usize = 16 * 1024;

        let mut input = [0u8; CHUNK];
        let mut output = [0u8; CHUNK * 2];
        let mut offset = self.offset;
        let mut remaining = self.length;
        while remaining > 0 {
            let wanted = usize::try_from(remaining.min(CHUNK as u64)).expect("chunk fits in usize");
            let read = self.source.read_at(offset, &mut input[..wanted])?;
            if read == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "artifact ended before the PKZIP data record",
                ));
            }
            for (index, byte) in input[..read].iter().enumerate() {
                output[index * 2] = HEX[usize::from(byte >> 4)];
                output[index * 2 + 1] = HEX[usize::from(byte & 0x0f)];
            }
            out.write_all(&output[..read * 2])?;
            offset += read as u64;
            remaining -= read as u64;
        }
        Ok(())
    }
}

/// PKZIP hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "PKZIP",
    slug = "pkzip",
    hashcat = [17200, 17210, 17220, 17225, 17230], john = ["PKZIP"],
    modes_fn = pkzip_modes,
)]
pub struct Pkzip {
    /// Signature variant (`pkzip`/`pkzip2`)
    #[field(role = other, encoding = ascii)]
    pub version: String,

    /// Archive payload
    #[field(role = ciphertext, encoding = ascii, ty = "String")]
    pub payload: PkzipPayload,
}

pub fn pkzip_modes(value: &Pkzip) -> Vec<crate::Mode> {
    let mut fields = value.payload.as_str().split('*');
    let Some(count) = fields
        .next()
        .and_then(|field| usize::from_str_radix(field, 16).ok())
    else {
        return Vec::new();
    };
    let Some(_checksum_size) = fields.next() else {
        return Vec::new();
    };
    let mut compression = Vec::with_capacity(count);
    let mut checksum_only = true;
    for _ in 0..count {
        let Some(data_type) = fields.next().and_then(|field| field.parse::<u8>().ok()) else {
            return Vec::new();
        };
        if fields.next().is_none() {
            return Vec::new();
        }
        if data_type > 1 {
            checksum_only = false;
            for _ in 0..5 {
                if fields.next().is_none() {
                    return Vec::new();
                }
            }
        }
        let Some(kind) = fields.next().and_then(|field| field.parse::<u8>().ok()) else {
            return Vec::new();
        };
        compression.push(kind);
        let skip = if value.version == "pkzip2" { 4 } else { 3 };
        for _ in 0..skip {
            if fields.next().is_none() {
                return Vec::new();
            }
        }
    }

    let compressed = compression.iter().all(|kind| *kind == 8);
    let uncompressed = compression.iter().all(|kind| *kind == 0);
    let mut modes = Vec::new();
    if count == 1 && !checksum_only {
        if compressed {
            modes.push(crate::Mode::Hashcat(17200));
            modes.push(crate::Mode::Hashcat(17220));
        } else if uncompressed {
            modes.push(crate::Mode::Hashcat(17210));
        }
        modes.push(crate::Mode::Hashcat(17225));
    } else if count == 1 {
        modes.push(crate::Mode::Hashcat(17225));
    } else {
        if compressed {
            modes.push(crate::Mode::Hashcat(17220));
        }
        modes.push(crate::Mode::Hashcat(17225));
        if count >= 3 {
            modes.push(crate::Mode::Hashcat(17230));
        }
    }
    if !modes.is_empty() {
        modes.push(crate::Mode::John("PKZIP"));
    }
    modes
}

impl Parse for Pkzip {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let (version, suffix) = if input.starts_with("$pkzip2$") {
            ("pkzip2", "$/pkzip2$")
        } else if input.starts_with("$pkzip$") {
            ("pkzip", "$/pkzip$")
        } else {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                0,
                "expected a PKZIP signature",
            ));
        };
        let payload = input
            .strip_prefix(if version == "pkzip2" {
                "$pkzip2$"
            } else {
                "$pkzip$"
            })
            .and_then(|rest| rest.strip_suffix(suffix))
            .ok_or_else(|| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    input.len(),
                    "missing PKZIP terminator",
                )
            })?;
        if payload.is_empty() {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                8,
                "PKZIP payload is empty",
            ));
        }
        Ok(Self {
            version: version.to_owned(),
            payload: PkzipPayload::Owned(payload.to_owned()),
        })
    }
}

impl Render for Pkzip {
    fn render_value(&self, opts: &RenderOptions) -> String {
        if matches!(self.payload, PkzipPayload::Streamed(_)) {
            let mut out = Vec::new();
            self.render_to(opts, &mut out)
                .expect("in-memory rendering cannot fail");
            return String::from_utf8(out).expect("PKZIP serialization is ASCII");
        }
        format!(
            "${}${}$/{}$",
            self.version,
            self.payload.as_str(),
            self.version
        )
    }

    fn render_to(
        &self,
        _opts: &RenderOptions,
        out: &mut dyn std::io::Write,
    ) -> std::io::Result<()> {
        match &self.payload {
            PkzipPayload::Owned(payload) => out
                .write_all(format!("${}${}$/{}$", self.version, payload, self.version).as_bytes()),
            PkzipPayload::Streamed(streamed) => {
                out.write_all(format!("${}${}", self.version, streamed.head).as_bytes())?;
                streamed.write_hex(out)?;
                out.write_all(format!("*$/{}$", self.version).as_bytes())
            }
        }
    }

    fn streams(&self) -> bool {
        matches!(self.payload, PkzipPayload::Streamed(_))
    }
}
