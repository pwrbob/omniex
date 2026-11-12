//! BMW, rendered as a bare hexadecimal digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// A single BMW digest.
///
/// The output size is selected by the hashcat mode; the serialized hash is
/// the digest alone.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "BMW",
    slug = "bmw",
    hashcat = [40121, 40122, 40123, 40124],
    modes_fn = bmw_modes,
)]
pub struct Bmw {
    /// Digest (variable length)
    #[field(role = digest, encoding = hex)]
    pub digest: Vec<u8>,
}

pub fn bmw_modes(value: &Bmw) -> Vec<crate::Mode> {
    match value.digest.len() {
        28 => vec![crate::Mode::Hashcat(40121)],
        32 => vec![crate::Mode::Hashcat(40122)],
        48 => vec![crate::Mode::Hashcat(40123)],
        64 => vec![crate::Mode::Hashcat(40124)],
        _ => Vec::new(),
    }
}

impl Parse for Bmw {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let digest = parse::decode_hex(input, 0)?;
        if !matches!(digest.len(), 28 | 32 | 48 | 64) {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                0,
                "BMW digests have an unsupported length",
            ));
        }
        Ok(Self { digest })
    }
}

impl Render for Bmw {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::hex(&self.digest)
    }
}
