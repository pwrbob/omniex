//! SecureCRT master passphrase hashes, rendered as
//! `S:"<name>"=<hex data>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// SecureCRT MasterPassphrase v2 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "SecureCRT MasterPassphrase v2", slug = "securecrt", hashcat = [31400])]
pub struct SecureCrt {
    /// Configuration key name
    #[field(role = other, encoding = ascii)]
    pub name: String,

    /// Encrypted data (colon-separated)
    #[field(role = ciphertext, encoding = ascii)]
    pub data: String,
}

impl Parse for SecureCrt {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "S:\"", 0)?;
        let (name, rest, rest_offset) = parse::split_once(rest, '"', 3)?;
        let rest = parse::strip_prefix(rest, "=", rest_offset)?;
        Ok(Self {
            name: name.to_owned(),
            data: rest.to_owned(),
        })
    }
}

impl Render for SecureCrt {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("S:\"{}\"={}", self.name, self.data)
    }
}
