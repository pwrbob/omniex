//! MySQL 4.1+ native password hashes, rendered as `*<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// MySQL 4.1+ native password hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "MySQL 4.1+", slug = "mysql-sha1", hashcat = [], john = ["mysql-sha1"])]
pub struct MysqlSha1 {
    /// 20-byte digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 20],
}

impl Parse for MysqlSha1 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "*", 0)?;
        Ok(Self {
            digest: parse::decode_hex_field::<20>(rest, 1, "digest")?,
        })
    }
}

impl Render for MysqlSha1 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("*{}", crate::format::hex(self.digest).to_uppercase())
    }
}
