//! AxCrypt 1 in-memory SHA1, rendered as `$axcrypt_sha1$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// AxCrypt 1 in-memory SHA1 hashes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "AxCrypt 1 in-memory SHA1",
    slug = "axcrypt-sha1",
    hashcat = [13300],
)]
pub struct AxcryptSha1 {
    /// 16-byte digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 16],
}

impl Parse for AxcryptSha1 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$axcrypt_sha1$", 0)?;
        Ok(Self {
            digest: parse::decode_hex_field::<16>(rest, 14, "digest")?,
        })
    }
}

impl Render for AxcryptSha1 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$axcrypt_sha1${}", crate::format::hex(self.digest))
    }
}
