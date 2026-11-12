//! Cisco-IOS `$9$`, rendered as `$9$<salt>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Cisco-IOS scrypt hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Cisco-IOS $9$ (scrypt)",
    slug = "cisco-ios9",
    hashcat = [9300],
)]
pub struct CiscoIos9 {
    /// 14-character salt
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// 43-character digest
    #[field(role = digest, encoding = ascii)]
    pub digest: String,
}

impl Parse for CiscoIos9 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$9$", 0)?;
        if rest.len() != 58 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                input.len(),
                "Cisco-IOS $9$ values are 61 characters",
            ));
        }
        Ok(Self {
            salt: rest[..14].to_owned(),
            digest: rest[15..].to_owned(),
        })
    }
}

impl Render for CiscoIos9 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$9${}${}", self.salt, self.digest)
    }
}
