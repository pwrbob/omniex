//! mscash hashes, rendered as `<user>:<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// MS Cache (mscash) hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "mscash", slug = "mscash", hashcat = [], john = ["mscash"])]
pub struct Mscash {
    /// User name.
    #[field(role = username, encoding = ascii)]
    pub username: String,

    /// Sixteen-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 16],
}

impl Parse for Mscash {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let (username, digest, digest_offset) = parse::split_once(input, ':', 0)?;
        Ok(Self {
            username: username.to_owned(),
            digest: parse::decode_hex_field::<16>(digest, digest_offset, "digest")?,
        })
    }
}

impl Render for Mscash {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("{}:{}", self.username, crate::format::hex(self.digest))
    }
}
