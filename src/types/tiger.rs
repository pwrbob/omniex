//! Tiger, rendered as a bare hexadecimal digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// A single Tiger digest.
///
/// The output size is selected by the hashcat mode; the serialized hash is
/// the digest alone.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Tiger",
    slug = "tiger",
    hashcat = [40090, 40091, 40089, 40092, 40093],
    modes_fn = tiger_modes,
)]
pub struct Tiger {
    /// Digest (variable length)
    #[field(role = digest, encoding = hex)]
    pub digest: Vec<u8>,
}

pub fn tiger_modes(value: &Tiger) -> Vec<crate::Mode> {
    match value.digest.len() {
        16 => vec![crate::Mode::Hashcat(40090)],
        20 => vec![crate::Mode::Hashcat(40091)],
        24 => vec![
            crate::Mode::Hashcat(40089),
            crate::Mode::Hashcat(40092),
            crate::Mode::Hashcat(40093),
        ],
        _ => Vec::new(),
    }
}

impl Parse for Tiger {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let digest = parse::decode_hex(input, 0)?;
        if !matches!(digest.len(), 16 | 20 | 24) {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                0,
                "Tiger digests have an unsupported length",
            ));
        }
        Ok(Self { digest })
    }
}

impl Render for Tiger {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::hex(&self.digest)
    }
}
