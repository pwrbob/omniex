//! Skein-512, rendered as a bare hexadecimal digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// A single Skein-512 digest.
///
/// The output size is selected by the hashcat mode; the serialized hash is
/// the digest alone.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Skein-512",
    slug = "skein-512",
    hashcat = [40096, 40097, 40098, 40099], john = ["skein-512"],
    modes_fn = skein_512_modes,
)]
pub struct Skein512 {
    /// The digest, whose length selects the Skein-512 output size.
    #[field(role = digest, encoding = hex)]
    pub digest: Vec<u8>,
}

pub fn skein_512_modes(value: &Skein512) -> Vec<crate::Mode> {
    match value.digest.len() {
        28 => vec![crate::Mode::Hashcat(40096)],
        32 => vec![crate::Mode::Hashcat(40097)],
        48 => vec![crate::Mode::Hashcat(40098)],
        64 => vec![crate::Mode::Hashcat(40099)],
        _ => Vec::new(),
    }
}

impl Parse for Skein512 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let digest = match input.strip_prefix("$skein$") {
            Some(rest) => parse::decode_hex(rest, 7)?,
            None => parse::decode_hex(input, 0)?,
        };
        if !matches!(digest.len(), 28 | 32 | 48 | 64) {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                0,
                "Skein-512 digests have an unsupported length",
            ));
        }
        Ok(Self { digest })
    }
}

impl Render for Skein512 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::hex(&self.digest)
    }
}
