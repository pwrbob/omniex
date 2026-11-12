//! Keccak, rendered as a bare hexadecimal digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// A single Keccak digest.
///
/// The output size is selected by the hashcat mode; the serialized hash is
/// the digest alone.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Keccak",
    slug = "keccak",
    hashcat = [17700, 17800, 17900, 18000],
    john = ["Raw-Keccak-256", "Raw-Keccak"],
    modes_fn = keccak_modes,
)]
pub struct Keccak {
    /// Digest (variable length)
    #[field(role = digest, encoding = hex)]
    pub digest: Vec<u8>,
}

pub fn keccak_modes(value: &Keccak) -> Vec<crate::Mode> {
    match value.digest.len() {
        28 => vec![crate::Mode::Hashcat(17700)],
        32 => vec![
            crate::Mode::Hashcat(17800),
            crate::Mode::John("Raw-Keccak-256"),
        ],
        48 => vec![crate::Mode::Hashcat(17900)],
        64 => vec![crate::Mode::Hashcat(18000), crate::Mode::John("Raw-Keccak")],
        _ => Vec::new(),
    }
}

impl Parse for Keccak {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let digest = parse::decode_hex(input, 0)?;
        if !matches!(digest.len(), 28 | 32 | 48 | 64) {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                0,
                "Keccak digests have an unsupported length",
            ));
        }
        Ok(Self { digest })
    }
}

impl Render for Keccak {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::hex(&self.digest)
    }
}
