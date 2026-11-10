//! John Oracle hashes, rendered as `O$<user>#<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// Oracle hashes in the John serialization.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Oracle legacy",
    slug = "oracle-legacy",
    hashcat = [],
    john = ["oracle"]
)]
pub struct OracleJohn {
    /// Oracle user name.
    #[field(role = username, encoding = ascii)]
    pub username: String,

    /// Eight-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 8],
}

impl Parse for OracleJohn {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "O$", 0)?;
        let (username, digest, digest_offset) = parse::split_once(rest, '#', 2)?;
        Ok(Self {
            username: username.to_owned(),
            digest: parse::decode_hex_field::<8>(digest, digest_offset, "digest")?,
        })
    }
}

impl Render for OracleJohn {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "O${}#{}",
            self.username,
            crate::format::hex(self.digest).to_uppercase()
        )
    }
}
