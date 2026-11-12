//! Google fscrypt hashes, rendered as `$fscrypt$<parameters>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Google fscrypt (Argon2id) hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "Google fscrypt", slug = "fscrypt", hashcat = [38900])]
pub struct Fscrypt {
    /// Version-specific fields
    #[field(role = other, encoding = ascii)]
    pub data: String,
}

impl Parse for Fscrypt {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$fscrypt$", 0)?;
        if rest.is_empty() {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                9,
                "missing fscrypt data",
            ));
        }
        Ok(Self {
            data: rest.to_owned(),
        })
    }
}

impl Render for Fscrypt {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$fscrypt${}", self.data)
    }
}
