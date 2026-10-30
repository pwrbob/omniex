//! RIPEMD, rendered as a bare hexadecimal digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// A single RIPEMD digest.
///
/// The variant and output size are selected by the hashcat mode.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "RIPEMD",
    slug = "ripemd",
    hashcat = [40086, 40173, 6000, 40087],
    modes_fn = ripemd_modes,
)]
pub struct Ripemd {
    /// The digest, whose length selects the RIPEMD variant.
    #[field(role = digest, encoding = hex)]
    pub digest: Vec<u8>,
}

pub fn ripemd_modes(value: &Ripemd) -> Vec<crate::Mode> {
    match value.digest.len() {
        16 => vec![crate::Mode::Hashcat(40086), crate::Mode::Hashcat(40173)],
        20 => vec![crate::Mode::Hashcat(6000)],
        32 => vec![crate::Mode::Hashcat(40087)],
        _ => Vec::new(),
    }
}

impl Parse for Ripemd {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let digest = parse::decode_hex(input, 0)?;
        if !matches!(digest.len(), 16 | 20 | 32) {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                0,
                "RIPEMD digests are 16, 20, or 32 bytes",
            ));
        }
        Ok(Self { digest })
    }
}

impl Render for Ripemd {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::hex(&self.digest)
    }
}
