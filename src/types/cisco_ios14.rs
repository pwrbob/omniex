//! Cisco-IOS `$14$` hashes, rendered as `$14$<salt>$<salt2>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// Cisco-IOS `$14$` hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "Cisco-IOS $14$", slug = "cisco-ios14", hashcat = [38200])]
pub struct CiscoIos14 {
    /// First salt.
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// Second salt.
    #[field(role = other, encoding = ascii)]
    pub salt2: String,

    /// Crypt base64 digest.
    #[field(role = digest, encoding = ascii)]
    pub digest: String,
}

impl Parse for CiscoIos14 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$14$", 0)?;
        let fields = parse::split_fields(rest, '$', 3)?;
        Ok(Self {
            salt: fields[0].0.to_owned(),
            salt2: fields[1].0.to_owned(),
            digest: fields[2].0.to_owned(),
        })
    }
}

impl Render for CiscoIos14 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$14${}${}${}", self.salt, self.salt2, self.digest)
    }
}
