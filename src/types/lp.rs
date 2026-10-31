//! LP hashes, rendered as `$lp$<email>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// LP (LastPass CLI) hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "LP", slug = "lp", hashcat = [], john = ["lp"])]
pub struct Lp {
    /// Account e-mail.
    #[field(role = username, encoding = ascii)]
    pub email: String,

    /// Sixteen-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 16],
}

impl Parse for Lp {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$lp$", 0)?;
        let (email, digest, digest_offset) = parse::split_once(rest, '$', 4)?;
        Ok(Self {
            email: email.to_owned(),
            digest: parse::decode_hex_field::<16>(digest, digest_offset, "digest")?,
        })
    }
}

impl Render for Lp {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$lp${}${}", self.email, crate::format::hex(self.digest))
    }
}
