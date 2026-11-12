//! PKZIP hashes, rendered as a `$pkzip$` or `$pkzip2$` payload.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

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
    #[field(role = ciphertext, encoding = ascii)]
    pub payload: String,
}

pub fn pkzip_modes(value: &Pkzip) -> Vec<crate::Mode> {
    let mut fields = value.payload.split('*');
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
    for _ in 0..count {
        let Some(data_type) = fields.next().and_then(|field| field.parse::<u8>().ok()) else {
            return Vec::new();
        };
        if fields.next().is_none() {
            return Vec::new();
        }
        if data_type > 1 {
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
    if count == 1 && compressed {
        modes.push(crate::Mode::Hashcat(17200));
        modes.push(crate::Mode::Hashcat(17220));
        modes.push(crate::Mode::Hashcat(17225));
    } else if count == 1 && uncompressed {
        modes.push(crate::Mode::Hashcat(17210));
        modes.push(crate::Mode::Hashcat(17225));
    } else if count > 1 {
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
            payload: payload.to_owned(),
        })
    }
}

impl Render for Pkzip {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("${}${}$/{}$", self.version, self.payload, self.version)
    }
}
