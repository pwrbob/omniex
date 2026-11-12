//! mega.nz password-protected link hashes, rendered as a single encoded blob.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// mega.nz password-protected link hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "mega.nz", slug = "mega", hashcat = [33400])]
pub struct Mega {
    /// Encoded salt/key material
    #[field(role = salt, encoding = ascii)]
    pub blob: String,
}

impl Parse for Mega {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "P!", 0)?;
        if rest.len() != 118 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                0,
                "mega.nz hashes are 120 characters",
            ));
        }
        Ok(Self {
            blob: rest.to_owned(),
        })
    }
}

impl Render for Mega {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("P!{}", self.blob)
    }
}
