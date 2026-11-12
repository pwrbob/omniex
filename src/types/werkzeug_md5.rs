//! Python Werkzeug MD5 hashes, rendered as `md5$<salt>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// Python Werkzeug MD5 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Python Werkzeug MD5",
    slug = "werkzeug-md5",
    hashcat = [30000]
)]
pub struct WerkzeugMd5 {
    /// Salt value
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// 16-byte digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 16],
}

impl Parse for WerkzeugMd5 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "md5$", 0)?;
        let (salt, digest, digest_offset) = parse::split_once(rest, '$', 4)?;
        Ok(Self {
            salt: salt.to_owned(),
            digest: parse::decode_hex_field::<16>(digest, digest_offset, "digest")?,
        })
    }
}

impl Render for WerkzeugMd5 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("md5${}${}", self.salt, crate::format::hex(self.digest))
    }
}
