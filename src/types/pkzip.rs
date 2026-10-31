//! PKZIP hashes, rendered as a `$pkzip$` or `$pkzip2$` payload.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// PKZIP hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "PKZIP",
    slug = "pkzip",
    hashcat = [17200, 17210, 17220, 17225, 17230],
    modes_fn = pkzip_modes,
)]
pub struct Pkzip {
    /// Signature variant, `pkzip` or `pkzip2`.
    #[field(role = other, encoding = ascii)]
    pub version: String,

    /// Archive payload, preserved verbatim.
    #[field(role = ciphertext, encoding = ascii)]
    pub payload: String,
}

pub fn pkzip_modes(_value: &Pkzip) -> Vec<crate::Mode> {
    vec![
        crate::Mode::Hashcat(17200),
        crate::Mode::Hashcat(17210),
        crate::Mode::Hashcat(17220),
        crate::Mode::Hashcat(17225),
        crate::Mode::Hashcat(17230),
    ]
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
