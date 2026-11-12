//! NetIQ SSPR (SHA-512 with Salt), rendered as `$sspr$4$<iterations>$<salt>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// NetIQ SSPR (SHA-512 with Salt) hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "NetIQ SSPR (SHA-512 with Salt)",
    slug = "sspr-sha512-salt",
    hashcat = [40062],
)]
pub struct SsprSha512Salt {
    /// Iteration count
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// Salt
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// 64-byte digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 64],
}

impl Parse for SsprSha512Salt {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$sspr$4$", 0)?;
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
            digest: parse::decode_hex_field::<64>(fields[2].0, fields[2].1, "digest")?,
        })
    }
}

impl Render for SsprSha512Salt {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$sspr$4${}${}${}",
            self.iterations,
            self.salt,
            crate::format::hex(self.digest)
        )
    }
}
