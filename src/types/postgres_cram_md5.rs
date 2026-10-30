//! PostgreSQL CRAM MD5, rendered as `$postgres$<user>*<salt>*<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// PostgreSQL CRAM MD5 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "PostgreSQL CRAM (MD5)",
    slug = "postgres-cram-md5",
    hashcat = [11100],
    john = ["postgres"],
)]
pub struct PostgresCramMd5 {
    /// Database username.
    #[field(role = username, encoding = ascii)]
    pub username: String,

    /// ASCII salt.
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// The 16-byte MD5 digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 16],
}

impl Parse for PostgresCramMd5 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$postgres$", 0)?;
        let fields = parse::split_fields(rest, '*', 3)?;
        let (username, _) = fields[0];
        let (salt, _) = fields[1];
        let (digest, digest_offset) = fields[2];
        Ok(Self {
            username: username.to_owned(),
            salt: salt.to_owned(),
            digest: parse::decode_hex_field::<16>(digest, 10 + digest_offset, "digest")?,
        })
    }
}

impl Render for PostgresCramMd5 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$postgres${}*{}*{}",
            self.username,
            self.salt,
            crate::format::hex(self.digest)
        )
    }
}
