//! Dovecot CRAM-MD5, rendered as `{CRAM-MD5}<challenge><digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Dovecot CRAM-MD5 hashes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "CRAM-MD5 Dovecot",
    slug = "cram-md5-dovecot",
    hashcat = [16400],
)]
pub struct CramMd5Dovecot {
    /// 16-byte challenge
    #[field(role = other, encoding = hex)]
    pub challenge: [u8; 16],

    /// 16-byte digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 16],
}

impl Parse for CramMd5Dovecot {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        if input.len() != 74 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                input.len(),
                "Dovecot CRAM-MD5 values are 74 characters",
            ));
        }
        let rest = parse::strip_prefix(input, "{CRAM-MD5}", 0)?;
        Ok(Self {
            challenge: parse::decode_hex_field::<16>(&rest[..32], 10, "challenge")?,
            digest: parse::decode_hex_field::<16>(&rest[32..], 42, "digest")?,
        })
    }
}

impl Render for CramMd5Dovecot {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "{{CRAM-MD5}}{}{}",
            crate::format::hex(self.challenge),
            crate::format::hex(self.digest)
        )
    }
}
