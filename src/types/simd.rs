//! SIMD, rendered as a bare hexadecimal digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// A single SIMD digest.
///
/// The output size is selected by the hashcat mode; the serialized hash is
/// the digest alone.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "SIMD",
    slug = "simd",
    hashcat = [40161, 40162, 40163, 40164],
    modes_fn = simd_modes,
)]
pub struct Simd {
    /// Digest (variable length)
    #[field(role = digest, encoding = hex)]
    pub digest: Vec<u8>,
}

pub fn simd_modes(value: &Simd) -> Vec<crate::Mode> {
    match value.digest.len() {
        28 => vec![crate::Mode::Hashcat(40161)],
        32 => vec![crate::Mode::Hashcat(40162)],
        48 => vec![crate::Mode::Hashcat(40163)],
        64 => vec![crate::Mode::Hashcat(40164)],
        _ => Vec::new(),
    }
}

impl Parse for Simd {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let digest = parse::decode_hex(input, 0)?;
        if !matches!(digest.len(), 28 | 32 | 48 | 64) {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                0,
                "SIMD digests have an unsupported length",
            ));
        }
        Ok(Self { digest })
    }
}

impl Render for Simd {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::hex(&self.digest)
    }
}
