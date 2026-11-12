//! Streebog, rendered as a bare hexadecimal digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// A single Streebog digest.
///
/// The output size is selected by the hashcat mode.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Streebog",
    slug = "streebog",
    hashcat = [11700, 11800],
    modes_fn = streebog_modes,
)]
pub struct Streebog {
    /// Digest (variable length)
    #[field(role = digest, encoding = hex)]
    pub digest: Vec<u8>,
}

pub fn streebog_modes(value: &Streebog) -> Vec<crate::Mode> {
    match value.digest.len() {
        32 => vec![crate::Mode::Hashcat(11700)],
        64 => vec![crate::Mode::Hashcat(11800)],
        _ => Vec::new(),
    }
}

impl Parse for Streebog {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let digest = parse::decode_hex(input, 0)?;
        if !matches!(digest.len(), 32 | 64) {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                0,
                "Streebog digests are 32 or 64 bytes",
            ));
        }
        Ok(Self { digest })
    }
}

impl Render for Streebog {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::hex(&self.digest)
    }
}
