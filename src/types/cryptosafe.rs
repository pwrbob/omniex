//! cryptoSafe hashes, rendered as `$cryptosafe$<version>$<payload>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// cryptoSafe hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "cryptoSafe", slug = "cryptosafe", hashcat = [], john = ["cryptoSafe"])]
pub struct Cryptosafe {
    /// Format version.
    #[field(role = other, encoding = decimal)]
    pub version: u8,

    /// Encoded payload.
    #[field(role = ciphertext, encoding = ascii)]
    pub payload: String,
}

impl Parse for Cryptosafe {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$cryptosafe$", 0)?;
        let (version, payload, payload_offset) = parse::split_once(rest, '$', 12)?;
        if payload.is_empty() {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                payload_offset,
                "missing cryptoSafe payload",
            ));
        }
        Ok(Self {
            version: version.parse::<u8>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    12,
                    "invalid cryptoSafe version",
                )
            })?,
            payload: payload.to_owned(),
        })
    }
}

impl Render for Cryptosafe {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$cryptosafe${}${}", self.version, self.payload)
    }
}
