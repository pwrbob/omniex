//! CRAM-MD5 challenge-response hashes, rendered as
//! `$cram_md5$<challenge>$<user> <digest>` in base64.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// CRAM-MD5 challenge-response hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "CRAM-MD5", slug = "cram-md5", hashcat = [10200])]
pub struct CramMd5 {
    /// Base64 challenge sent by the server.
    #[field(role = salt, encoding = base64)]
    pub challenge: Vec<u8>,

    /// User name echoed in the response.
    #[field(role = other, encoding = ascii)]
    pub user: String,

    /// Sixteen-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 16],
}

impl Parse for CramMd5 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$cram_md5$", 0)?;
        let (challenge, response, response_offset) = parse::split_once(rest, '$', 10)?;
        let decoded = parse::decode_base64(response, response_offset)?;
        let response = std::str::from_utf8(&decoded).map_err(|_| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                response_offset,
                "CRAM-MD5 response is not ASCII",
            )
        })?;
        let (user, digest) = response.rsplit_once(' ').ok_or_else(|| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                response_offset,
                "CRAM-MD5 response has no digest",
            )
        })?;
        Ok(Self {
            challenge: parse::decode_base64(challenge, 10)?,
            user: user.to_owned(),
            digest: parse::decode_hex_field::<16>(digest, response_offset, "digest")?,
        })
    }
}

impl Render for CramMd5 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$cram_md5${}${}",
            crate::format::base64(&self.challenge),
            crate::format::base64(
                format!("{} {}", self.user, crate::format::hex(self.digest)).as_bytes()
            )
        )
    }
}
