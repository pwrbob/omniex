//! SipHash, rendered as `<digest>:<c>:<d>:<key>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// SipHash values.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "SipHash",
    slug = "siphash",
    hashcat = [10100],
)]
pub struct Siphash {
    /// The 8-byte hash value.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 8],

    /// Compression rounds parameter.
    #[field(role = other, encoding = decimal)]
    pub compression_rounds: u8,

    /// Finalization rounds parameter.
    #[field(role = other, encoding = decimal)]
    pub finalization_rounds: u8,

    /// The 16-byte key.
    #[field(role = key, encoding = hex)]
    pub key: [u8; 16],
}

impl Parse for Siphash {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        let fields = parse::split_fields(input, ':', 4)?;
        let (digest, digest_offset) = fields[0];
        let (compression, compression_offset) = fields[1];
        let (finalization, finalization_offset) = fields[2];
        let (key, key_offset) = fields[3];

        Ok(Self {
            digest: parse::decode_hex_field::<8>(digest, digest_offset, "digest")?,
            compression_rounds: compression.parse::<u8>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    compression_offset,
                    "invalid SipHash compression round count",
                )
            })?,
            finalization_rounds: finalization.parse::<u8>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    finalization_offset,
                    "invalid SipHash finalization round count",
                )
            })?,
            key: parse::decode_hex_field::<16>(key, key_offset, "key")?,
        })
    }
}

impl Render for Siphash {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "{}:{}:{}:{}",
            crate::format::hex(self.digest),
            self.compression_rounds,
            self.finalization_rounds,
            crate::format::hex(self.key)
        )
    }
}
