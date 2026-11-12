//! MySQL caching_sha2_password fast auth, rendered as `$mysqlsha2$<challenge>*<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// MySQL caching_sha2_password challenge-response hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "MySQL caching_sha2_password challenge-response",
    slug = "mysql-caching-sha2",
    hashcat = [40006],
)]
pub struct MysqlCachingSha2 {
    /// Challenge
    #[field(role = other, encoding = hex)]
    pub challenge: Vec<u8>,

    /// 32-byte SHA2-256 digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 32],
}

impl Parse for MysqlCachingSha2 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$mysqlsha2$", 0)?;
        let (challenge, digest, digest_offset) = parse::split_once(rest, '*', 11)?;
        Ok(Self {
            challenge: parse::decode_hex(challenge, 11)?,
            digest: parse::decode_hex_field::<32>(digest, 11 + digest_offset, "digest")?,
        })
    }
}

impl Render for MysqlCachingSha2 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$mysqlsha2${}*{}",
            crate::format::hex(&self.challenge),
            crate::format::hex(self.digest)
        )
    }
}
