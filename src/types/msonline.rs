//! Microsoft Online Account hashes, rendered as
//! `$MSONLINEACCOUNT$<version>$<iterations>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Microsoft Online Account hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Microsoft Online Account",
    slug = "microsoft-online",
    hashcat = [33700]
)]
pub struct MicrosoftOnline {
    /// Format version
    #[field(role = other, encoding = decimal)]
    pub version: u8,

    /// Iteration count
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// 32-byte digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 32],
}

impl Parse for MicrosoftOnline {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$MSONLINEACCOUNT$", 0)?;
        let fields = parse::split_fields(rest, '$', 3)?;
        let version = fields[0].0.parse::<u8>().map_err(|_| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                fields[0].1,
                "invalid Microsoft Online version",
            )
        })?;
        let iterations = fields[1].0.parse::<u32>().map_err(|_| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                fields[1].1,
                "invalid Microsoft Online iteration count",
            )
        })?;
        Ok(Self {
            version,
            iterations,
            digest: parse::decode_hex_field::<32>(fields[2].0, fields[2].1, "digest")?,
        })
    }
}

impl Render for MicrosoftOnline {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$MSONLINEACCOUNT${}${}${}",
            self.version,
            self.iterations,
            crate::format::hex(self.digest)
        )
    }
}
