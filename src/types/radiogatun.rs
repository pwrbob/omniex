//! RadioGatun, rendered as a bare hexadecimal digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// A single RadioGatun digest.
///
/// The output size is selected by the hashcat mode; the serialized hash is
/// the digest alone.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "RadioGatun",
    slug = "radiogatun",
    hashcat = [40171, 40172],
    modes_fn = radiogatun_modes,
)]
pub struct RadioGatun {
    /// Digest (variable length)
    #[field(role = digest, encoding = hex)]
    pub digest: Vec<u8>,
}

pub fn radiogatun_modes(value: &RadioGatun) -> Vec<crate::Mode> {
    match value.digest.len() {
        16 => vec![crate::Mode::Hashcat(40171)],
        32 => vec![crate::Mode::Hashcat(40172)],
        _ => Vec::new(),
    }
}

impl Parse for RadioGatun {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let digest = parse::decode_hex(input, 0)?;
        if !matches!(digest.len(), 16 | 32) {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                0,
                "RadioGatun digests have an unsupported length",
            ));
        }
        Ok(Self { digest })
    }
}

impl Render for RadioGatun {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::hex(&self.digest)
    }
}
