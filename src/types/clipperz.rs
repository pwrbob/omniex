//! Clipperz hashes, rendered as `$clipperz$<digest>$<salt>*<username>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Clipperz hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "Clipperz", slug = "clipperz", hashcat = [], john = ["Clipperz"])]
pub struct Clipperz {
    /// 32-byte digest
    #[field(role = digest, encoding = ascii)]
    pub digest: String,

    /// 32-byte salt
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// Account e-mail
    #[field(role = username, encoding = ascii)]
    pub email: String,
}

impl Parse for Clipperz {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$clipperz$", 0)?;
        let (digest, rest, rest_offset) = parse::split_once(rest, '$', 10)?;
        let (salt, email, email_offset) = parse::split_once(rest, '*', rest_offset)?;
        if email.is_empty() {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                email_offset,
                "missing Clipperz e-mail",
            ));
        }
        Ok(Self {
            digest: digest.to_owned(),
            salt: salt.to_owned(),
            email: email.to_owned(),
        })
    }
}

impl Render for Clipperz {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$clipperz${}${}*{}", self.digest, self.salt, self.email)
    }
}
