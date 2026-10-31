//! FreeBSD GELI hashes, rendered as `$geli$<data>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// FreeBSD GELI hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "FreeBSD GELI", slug = "geli", hashcat = [38700], john = ["geli"])]
pub struct Geli {
    /// Version-specific fields, preserved verbatim.
    #[field(role = other, encoding = ascii)]
    pub data: String,
}

impl Parse for Geli {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$geli$", 0)?;
        if rest.is_empty() {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                6,
                "missing GELI data",
            ));
        }
        Ok(Self {
            data: rest.to_owned(),
        })
    }
}

impl Render for Geli {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$geli${}", self.data)
    }
}
