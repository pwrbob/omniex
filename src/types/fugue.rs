//! Fugue, rendered as a bare hexadecimal digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// A single Fugue digest.
///
/// The output size is selected by the hashcat mode; the serialized hash is
/// the digest alone.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Fugue",
    slug = "fugue",
    hashcat = [40133, 40134, 40135, 40136],
    modes_fn = fugue_modes,
)]
pub struct Fugue {
    /// The digest, whose length selects the Fugue output size.
    #[field(role = digest, encoding = hex)]
    pub digest: Vec<u8>,
}

pub fn fugue_modes(value: &Fugue) -> Vec<crate::Mode> {
    match value.digest.len() {
        28 => vec![crate::Mode::Hashcat(40133)],
        32 => vec![crate::Mode::Hashcat(40134)],
        48 => vec![crate::Mode::Hashcat(40135)],
        64 => vec![crate::Mode::Hashcat(40136)],
        _ => Vec::new(),
    }
}

impl Parse for Fugue {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let digest = parse::decode_hex(input, 0)?;
        if !matches!(digest.len(), 28 | 32 | 48 | 64) {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                0,
                "Fugue digests have an unsupported length",
            ));
        }
        Ok(Self { digest })
    }
}

impl Render for Fugue {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::hex(&self.digest)
    }
}
