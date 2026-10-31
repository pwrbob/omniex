//! OpenSSL enc hashes, rendered as a `$openssl$` field sequence.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// OpenSSL `enc` hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "OpenSSL enc", slug = "openssl-enc", hashcat = [], john = ["openssl-enc"])]
pub struct OpensslEnc {
    /// Version-specific fields, preserved verbatim.
    #[field(role = other, encoding = ascii)]
    pub fields: String,
}

impl Parse for OpensslEnc {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$openssl$", 0)?;
        if rest.is_empty() {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                9,
                "missing OpenSSL fields",
            ));
        }
        Ok(Self {
            fields: rest.to_owned(),
        })
    }
}

impl Render for OpensslEnc {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$openssl${}", self.fields)
    }
}
