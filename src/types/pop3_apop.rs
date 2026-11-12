//! POP3 APOP, rendered as `$apop$<challenge>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// POP3 APOP hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "POP3 APOP",
    slug = "pop3-apop",
    hashcat = [37601],
)]
pub struct Pop3Apop {
    /// Server challenge text
    #[field(role = other, encoding = ascii)]
    pub challenge: String,

    /// 16-byte MD5 digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 16],
}

impl Parse for Pop3Apop {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$apop$", 0)?;
        let (challenge, digest, digest_offset) = parse::split_once(rest, '$', 6)?;
        if challenge.is_empty() {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                6,
                "POP3 APOP challenge must not be empty",
            ));
        }
        Ok(Self {
            challenge: challenge.to_owned(),
            digest: parse::decode_hex_field::<16>(digest, 6 + digest_offset, "digest")?,
        })
    }
}

impl Render for Pop3Apop {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$apop${}${}",
            self.challenge,
            crate::format::hex(self.digest)
        )
    }
}
