//! NetIQ SSPR (SHA-1 with Salt), rendered as `$sspr$2$<iterations>$<salt>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// NetIQ SSPR (SHA-1 with Salt) hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "NetIQ SSPR (SHA-1 with Salt)",
    slug = "sspr-sha1-salt",
    hashcat = [40059],
)]
pub struct SsprSha1Salt {
    /// Iteration count
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// Salt
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// 20-byte digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 20],
}

impl Parse for SsprSha1Salt {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$sspr$2$", 0)?;
        let fields = parse::split_fields(rest, '$', 3)?;
        let iterations = fields[0].0.parse::<u32>().map_err(|_| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                8,
                "invalid SSPR iteration count",
            )
        })?;
        Ok(Self {
            iterations,
            salt: fields[1].0.to_owned(),
            digest: parse::decode_hex_field::<20>(fields[2].0, fields[2].1, "digest")?,
        })
    }
}

impl Render for SsprSha1Salt {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$sspr$2${}${}${}",
            self.iterations,
            self.salt,
            crate::format::hex(self.digest)
        )
    }
}
