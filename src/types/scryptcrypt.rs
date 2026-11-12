//! scryptcrypt hashes, rendered as `$7$<setting>$<checksum>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// scryptcrypt (Unix scrypt) hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "scryptcrypt", slug = "scryptcrypt", hashcat = [36300])]
pub struct Scryptcrypt {
    /// Salt and parameter setting
    #[field(role = salt, encoding = ascii)]
    pub setting: String,

    /// Checksum
    #[field(role = digest, encoding = ascii)]
    pub checksum: String,
}

impl Parse for Scryptcrypt {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$7$", 0)?;
        let (setting, checksum, _) = parse::split_once(rest, '$', 3)?;
        Ok(Self {
            setting: setting.to_owned(),
            checksum: checksum.to_owned(),
        })
    }
}

impl Render for Scryptcrypt {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$7${}${}", self.setting, self.checksum)
    }
}
