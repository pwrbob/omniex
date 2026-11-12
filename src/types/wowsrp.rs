//! WoWSRP hashes, rendered as `<user>:$WoWSRP$<data>$<salt>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// WoWSRP hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "WoWSRP", slug = "wowsrp", hashcat = [], john = ["WoWSRP"])]
pub struct Wowsrp {
    /// User name
    #[field(role = username, encoding = ascii)]
    pub username: String,

    /// Session data
    #[field(role = other, encoding = ascii)]
    pub data: String,

    /// Salt
    #[field(role = salt, encoding = ascii)]
    pub salt: String,
}

impl Parse for Wowsrp {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let (username, rest, rest_offset) = parse::split_once(input, ':', 0)?;
        let rest = parse::strip_prefix(rest, "$WoWSRP$", rest_offset)?;
        let (data, salt, salt_offset) = parse::split_once(rest, '$', rest_offset + 8)?;
        if salt.is_empty() {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                salt_offset,
                "missing WoWSRP salt",
            ));
        }
        Ok(Self {
            username: username.to_owned(),
            data: data.to_owned(),
            salt: salt.to_owned(),
        })
    }
}

impl Render for Wowsrp {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("{}:$WoWSRP${}${}", self.username, self.data, self.salt)
    }
}
