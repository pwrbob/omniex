//! JH, rendered as a bare hexadecimal digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// A single JH digest.
///
/// The output size is selected by the hashcat mode; the serialized hash is
/// the digest alone.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "JH",
    slug = "jh",
    hashcat = [40145, 40146, 40147, 40148],
    modes_fn = jh_modes,
)]
pub struct Jh {
    /// Digest (variable length)
    #[field(role = digest, encoding = hex)]
    pub digest: Vec<u8>,
}

pub fn jh_modes(value: &Jh) -> Vec<crate::Mode> {
    match value.digest.len() {
        28 => vec![crate::Mode::Hashcat(40145)],
        32 => vec![crate::Mode::Hashcat(40146)],
        48 => vec![crate::Mode::Hashcat(40147)],
        64 => vec![crate::Mode::Hashcat(40148)],
        _ => Vec::new(),
    }
}

impl Parse for Jh {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let digest = parse::decode_hex(input, 0)?;
        if !matches!(digest.len(), 28 | 32 | 48 | 64) {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                0,
                "JH digests have an unsupported length",
            ));
        }
        Ok(Self { digest })
    }
}

impl Render for Jh {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::hex(&self.digest)
    }
}
