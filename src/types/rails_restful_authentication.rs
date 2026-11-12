//! Ruby on Rails Restful-Authentication, rendered as `<digest>:<salt>:<sitekey>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// Ruby on Rails Restful-Authentication hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Ruby on Rails Restful-Authentication",
    slug = "rails-restful-authentication",
    hashcat = [19500],
)]
pub struct RailsRestfulAuthentication {
    /// 20-byte SHA1 digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 20],

    /// Salt
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// Site key
    #[field(role = key, encoding = ascii)]
    pub site_key: String,
}

impl Parse for RailsRestfulAuthentication {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let fields = parse::split_fields(input, ':', 3)?;
        Ok(Self {
            digest: parse::decode_hex_field::<20>(fields[0].0, fields[0].1, "digest")?,
            salt: fields[1].0.to_owned(),
            site_key: fields[2].0.to_owned(),
        })
    }
}

impl Render for RailsRestfulAuthentication {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "{}:{}:{}",
            crate::format::hex(self.digest),
            self.salt,
            self.site_key
        )
    }
}
