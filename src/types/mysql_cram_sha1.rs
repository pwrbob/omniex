//! MySQL CRAM SHA1, rendered as `$mysqlna$<challenge>*<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// MySQL CRAM SHA1 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "MySQL CRAM (SHA1)",
    slug = "mysql-cram-sha1",
    hashcat = [11200],
)]
pub struct MysqlCramSha1 {
    /// Decimal challenge value.
    #[field(role = other, encoding = ascii)]
    pub challenge: String,

    /// The 20-byte SHA1 digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 20],
}

impl Parse for MysqlCramSha1 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$mysqlna$", 0)?;
        let (challenge, digest, digest_offset) = parse::split_once(rest, '*', 9)?;
        if challenge.is_empty() || !challenge.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                9,
                "MySQL challenge must be decimal",
            ));
        }
        Ok(Self {
            challenge: challenge.to_owned(),
            digest: parse::decode_hex_field::<20>(digest, 9 + digest_offset, "digest")?,
        })
    }
}

impl Render for MysqlCramSha1 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$mysqlna${}*{}",
            self.challenge,
            crate::format::hex(self.digest)
        )
    }
}
