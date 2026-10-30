//! SHAvite-3, rendered as a bare hexadecimal digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// A single SHAvite-3 digest.
///
/// The output size is selected by the hashcat mode; the serialized hash is
/// the digest alone.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "SHAvite-3",
    slug = "shavite3",
    hashcat = [40157, 40158, 40159, 40160],
    modes_fn = shavite3_modes,
)]
pub struct Shavite3 {
    /// The digest, whose length selects the SHAvite-3 output size.
    #[field(role = digest, encoding = hex)]
    pub digest: Vec<u8>,
}

pub fn shavite3_modes(value: &Shavite3) -> Vec<crate::Mode> {
    match value.digest.len() {
        28 => vec![crate::Mode::Hashcat(40157)],
        32 => vec![crate::Mode::Hashcat(40158)],
        48 => vec![crate::Mode::Hashcat(40159)],
        64 => vec![crate::Mode::Hashcat(40160)],
        _ => Vec::new(),
    }
}

impl Parse for Shavite3 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let digest = parse::decode_hex(input, 0)?;
        if !matches!(digest.len(), 28 | 32 | 48 | 64) {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                0,
                "SHAvite-3 digests have an unsupported length",
            ));
        }
        Ok(Self { digest })
    }
}

impl Render for Shavite3 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::hex(&self.digest)
    }
}
