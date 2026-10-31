//! PostgreSQL SCRAM-SHA-256 hashes, rendered as
//! `SCRAM-SHA-256$<iterations>:<salt>$<stored key>:<server key>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// PostgreSQL SCRAM-SHA-256 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "PostgreSQL SCRAM-SHA-256",
    slug = "postgres-scram-sha256",
    hashcat = [40055]
)]
pub struct PostgresScramSha256 {
    /// Iteration count.
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// Base64 salt.
    #[field(role = salt, encoding = base64)]
    pub salt: Vec<u8>,

    /// Base64 stored key.
    #[field(role = digest, encoding = base64)]
    pub stored_key: Vec<u8>,

    /// Base64 server key.
    #[field(role = other, encoding = base64)]
    pub server_key: Vec<u8>,
}

impl Parse for PostgresScramSha256 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "SCRAM-SHA-256$", 0)?;
        let fields = parse::split_fields(rest, '$', 2)?;
        let (iterations, salt, salt_offset) = parse::split_once(fields[0].0, ':', fields[0].1)?;
        let (stored_key, server_key, server_key_offset) =
            parse::split_once(fields[1].0, ':', fields[1].1)?;
        Ok(Self {
            iterations: iterations.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    14,
                    "invalid PostgreSQL iteration count",
                )
            })?,
            salt: parse::decode_base64(salt, salt_offset)?,
            stored_key: parse::decode_base64(stored_key, fields[1].1)?,
            server_key: parse::decode_base64(server_key, server_key_offset)?,
        })
    }
}

impl Render for PostgresScramSha256 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "SCRAM-SHA-256${}:{}${}:{}",
            self.iterations,
            crate::format::base64(&self.salt),
            crate::format::base64(&self.stored_key),
            crate::format::base64(&self.server_key)
        )
    }
}
