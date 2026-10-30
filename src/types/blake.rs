//! BLAKE, rendered as a bare hexadecimal digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// A single BLAKE digest.
///
/// The output size is selected by the hashcat mode; the serialized hash is
/// the digest alone.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "BLAKE",
    slug = "blake",
    hashcat = [40117, 40118, 40119, 40120],
    modes_fn = blake_modes,
)]
pub struct Blake {
    /// The digest, whose length selects the BLAKE output size.
    #[field(role = digest, encoding = hex)]
    pub digest: Vec<u8>,
}

pub fn blake_modes(value: &Blake) -> Vec<crate::Mode> {
    match value.digest.len() {
        28 => vec![crate::Mode::Hashcat(40117)],
        32 => vec![crate::Mode::Hashcat(40118)],
        48 => vec![crate::Mode::Hashcat(40119)],
        64 => vec![crate::Mode::Hashcat(40120)],
        _ => Vec::new(),
    }
}

impl Parse for Blake {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let digest = parse::decode_hex(input, 0)?;
        if !matches!(digest.len(), 28 | 32 | 48 | 64) {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                0,
                "BLAKE digests have an unsupported length",
            ));
        }
        Ok(Self { digest })
    }
}

impl Render for Blake {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::hex(&self.digest)
    }
}
