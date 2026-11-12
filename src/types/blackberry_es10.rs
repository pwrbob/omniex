//! BlackBerry ES10 hashes, rendered as `$bbes10$<digest>$<salt>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// BlackBerry ES10 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "BlackBerry ES10", slug = "blackberry-es10", hashcat = [], john = ["Blackberry-ES10"])]
pub struct BlackberryEs10 {
    /// 32-byte digest
    #[field(role = digest, encoding = ascii)]
    pub digest: String,

    /// 4-byte salt
    #[field(role = salt, encoding = ascii)]
    pub salt: String,
}

impl Parse for BlackberryEs10 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$bbes10$", 0)?;
        let (digest, salt, salt_offset) = parse::split_once(rest, '$', 8)?;
        if salt.is_empty() {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                salt_offset,
                "missing BlackBerry salt",
            ));
        }
        Ok(Self {
            digest: digest.to_owned(),
            salt: salt.to_owned(),
        })
    }
}

impl Render for BlackberryEs10 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$bbes10${}${}", self.digest, self.salt)
    }
}
