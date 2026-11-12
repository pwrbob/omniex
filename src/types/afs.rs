//! AFS hashes, rendered as `$K4$<salt>,<data>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// AFS hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "AFS", slug = "afs", hashcat = [], john = ["AFS"])]
pub struct Afs {
    /// 8-byte salt as hexadecimal
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// Encoded data
    #[field(role = digest, encoding = ascii)]
    pub data: String,
}

impl Parse for Afs {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$K4$", 0)?;
        let (salt, data, data_offset) = parse::split_once(rest, ',', 4)?;
        if data.is_empty() {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                data_offset,
                "missing AFS data",
            ));
        }
        Ok(Self {
            salt: salt.to_owned(),
            data: data.to_owned(),
        })
    }
}

impl Render for Afs {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$K4${},{}", self.salt, self.data)
    }
}
