//! RedHat 389-DS LDAP PBKDF2-SHA256 hashes, rendered as
//! `{PBKDF2_SHA256}<base64>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// RedHat 389-DS LDAP PBKDF2-SHA256 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "RedHat 389-DS LDAP",
    slug = "redhat-389ds",
    hashcat = [40025]
)]
pub struct Redhat389ds {
    /// Salt and digest payload
    #[field(role = salt, encoding = base64)]
    pub payload: Vec<u8>,
}

impl Parse for Redhat389ds {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "{PBKDF2_SHA256}", 0)?;
        Ok(Self {
            payload: parse::decode_base64(rest, 14)?,
        })
    }
}

impl Render for Redhat389ds {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("{{PBKDF2_SHA256}}{}", crate::format::base64(&self.payload))
    }
}
