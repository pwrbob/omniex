//! John HMAC formats, rendered as `<key>#<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// John HMAC hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "HMAC legacy",
    slug = "hmac-legacy",
    hashcat = [],
    john = ["HMAC-MD5", "HMAC-SHA1", "HMAC-SHA256", "HMAC-SHA512"],
    modes_fn = john_hmac_modes,
)]
pub struct JohnHmac {
    /// HMAC key
    #[field(role = key, encoding = ascii)]
    pub key: String,

    /// Digest (variable length)
    #[field(role = digest, encoding = hex)]
    pub digest: Vec<u8>,
}

pub fn john_hmac_modes(value: &JohnHmac) -> Vec<crate::Mode> {
    match value.digest.len() {
        16 => vec![crate::Mode::John("HMAC-MD5")],
        20 => vec![crate::Mode::John("HMAC-SHA1")],
        32 => vec![crate::Mode::John("HMAC-SHA256")],
        64 => vec![crate::Mode::John("HMAC-SHA512")],
        _ => Vec::new(),
    }
}

impl Parse for JohnHmac {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let (key, digest, digest_offset) = parse::split_once(input, '#', 0)?;
        let digest = parse::decode_hex(digest, digest_offset)?;
        if !matches!(digest.len(), 16 | 20 | 32 | 64) {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                digest_offset,
                "HMAC digests are 16, 20, 32, or 64 bytes",
            ));
        }
        Ok(Self {
            key: key.to_owned(),
            digest,
        })
    }
}

impl Render for JohnHmac {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("{}#{}", self.key, crate::format::hex(&self.digest))
    }
}
