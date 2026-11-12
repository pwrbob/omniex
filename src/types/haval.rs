//! HAVAL, rendered as a bare hexadecimal digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// A single HAVAL digest.
///
/// The number of passes and the output size are selected by the hashcat mode;
/// the serialized hash is the digest alone.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "HAVAL",
    slug = "haval",
    hashcat = [
        40102, 40103, 40104, 40105, 40106, 40107, 40108, 40109, 40110, 40111, 40112, 40113, 40114,
        40115, 40116,
    ],
    modes_fn = haval_modes,
)]
pub struct Haval {
    /// Digest (variable length)
    #[field(role = digest, encoding = hex)]
    pub digest: Vec<u8>,
}

pub fn haval_modes(value: &Haval) -> Vec<crate::Mode> {
    Haval::DESCRIPTOR
        .all_modes
        .iter()
        .copied()
        .filter(|mode| {
            let crate::Mode::Hashcat(mode) = mode else {
                return false;
            };
            let length = match mode {
                40102..=40104 => 16,
                40105..=40107 => 20,
                40108..=40110 => 24,
                40111..=40113 => 28,
                _ => 32,
            };
            value.digest.len() == length
        })
        .collect()
}

impl Parse for Haval {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let digest = parse::decode_hex(input, 0)?;
        if !matches!(digest.len(), 16 | 20 | 24 | 28 | 32) {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                0,
                "HAVAL digests are 16, 20, 24, 28, or 32 bytes",
            ));
        }
        Ok(Self { digest })
    }
}

impl Render for Haval {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::hex(&self.digest)
    }
}
