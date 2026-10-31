//! Oracle O10GLOGON hashes, rendered as a `$o10glogon$` field sequence.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Oracle O10GLOGON hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Oracle O10GLOGON",
    slug = "o10glogon",
    hashcat = [],
    john = ["o10glogon"]
)]
pub struct O10glogon {
    /// User name.
    #[field(role = username, encoding = ascii)]
    pub username: String,

    /// First digest.
    #[field(role = digest, encoding = ascii)]
    pub digest1: String,

    /// Second digest.
    #[field(role = other, encoding = ascii)]
    pub digest2: String,

    /// Remaining fields.
    #[field(role = other, encoding = ascii)]
    pub rest: String,
}

impl Parse for O10glogon {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$o10glogon$", 0)?;
        let parts = rest.splitn(4, '$').collect::<Vec<_>>();
        if parts.len() < 3 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                rest.len(),
                "O10GLOGON hashes have at least three fields",
            ));
        }
        Ok(Self {
            username: parts[0].to_owned(),
            digest1: parts[1].to_owned(),
            digest2: parts[2].to_owned(),
            rest: parts.get(3).copied().unwrap_or_default().to_owned(),
        })
    }
}

impl Render for O10glogon {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        let mut value = format!(
            "$o10glogon${}${}${}",
            self.username, self.digest1, self.digest2
        );
        if !self.rest.is_empty() {
            value.push('$');
            value.push_str(&self.rest);
        }
        value
    }
}
