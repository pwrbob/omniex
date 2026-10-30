//! NetIQ SSPR (MD5), rendered as `$sspr$0$<iterations>$NONE$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// NetIQ SSPR (MD5) hashes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "NetIQ SSPR (MD5)",
    slug = "sspr-md5",
    hashcat = [40057],
)]
pub struct SsprMd5 {
    /// Iteration count.
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// The 16-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 16],
}

impl Parse for SsprMd5 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$sspr$0$", 0)?;
        let (iterations, rest, rest_offset) = parse::split_once(rest, '$', 8)?;
        let rest = parse::strip_prefix(rest, "NONE$", 8 + rest_offset)?;
        let iterations = iterations.parse::<u32>().map_err(|_| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                8,
                "invalid SSPR iteration count",
            )
        })?;
        let digest_offset = 8 + rest_offset + 5;
        Ok(Self {
            iterations,
            digest: parse::decode_hex_field::<16>(rest, digest_offset, "digest")?,
        })
    }
}

impl Render for SsprMd5 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$sspr$0${}$NONE${}",
            self.iterations,
            crate::format::hex(self.digest)
        )
    }
}
