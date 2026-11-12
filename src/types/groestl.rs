//! Groestl, rendered as a bare hexadecimal digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// A single Groestl digest.
///
/// The output size is selected by the hashcat mode; the serialized hash is
/// the digest alone.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Groestl",
    slug = "groestl",
    hashcat = [40137, 40138, 40139, 40140],
    modes_fn = groestl_modes,
)]
pub struct Groestl {
    /// Digest (variable length)
    #[field(role = digest, encoding = hex)]
    pub digest: Vec<u8>,
}

pub fn groestl_modes(value: &Groestl) -> Vec<crate::Mode> {
    match value.digest.len() {
        28 => vec![crate::Mode::Hashcat(40137)],
        32 => vec![crate::Mode::Hashcat(40138)],
        48 => vec![crate::Mode::Hashcat(40139)],
        64 => vec![crate::Mode::Hashcat(40140)],
        _ => Vec::new(),
    }
}

impl Parse for Groestl {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let digest = parse::decode_hex(input, 0)?;
        if !matches!(digest.len(), 28 | 32 | 48 | 64) {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                0,
                "Groestl digests have an unsupported length",
            ));
        }
        Ok(Self { digest })
    }
}

impl Render for Groestl {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::hex(&self.digest)
    }
}
