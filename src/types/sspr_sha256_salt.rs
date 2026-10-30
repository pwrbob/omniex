//! NetIQ SSPR (SHA-256 with Salt), rendered as `$sspr$3$<iterations>$<salt>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// NetIQ SSPR (SHA-256 with Salt) hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "NetIQ SSPR (SHA-256 with Salt)",
    slug = "sspr-sha256-salt",
    hashcat = [40060],
)]
pub struct SsprSha256Salt {
    /// Iteration count.
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// ASCII salt.
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// The 32-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 32],
}

impl Parse for SsprSha256Salt {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$sspr$3$", 0)?;
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
            digest: parse::decode_hex_field::<32>(fields[2].0, fields[2].1, "digest")?,
        })
    }
}

impl Render for SsprSha256Salt {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$sspr$3${}${}${}",
            self.iterations,
            self.salt,
            crate::format::hex(self.digest)
        )
    }
}
