//! CubeHash, rendered as a bare hexadecimal digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// A single CubeHash digest.
///
/// The output size is selected by the hashcat mode; the serialized hash is
/// the digest alone.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "CubeHash",
    slug = "cubehash",
    hashcat = [40125, 40126, 40127, 40128],
    modes_fn = cubehash_modes,
)]
pub struct CubeHash {
    /// Digest (variable length)
    #[field(role = digest, encoding = hex)]
    pub digest: Vec<u8>,
}

pub fn cubehash_modes(value: &CubeHash) -> Vec<crate::Mode> {
    match value.digest.len() {
        28 => vec![crate::Mode::Hashcat(40125)],
        32 => vec![crate::Mode::Hashcat(40126)],
        48 => vec![crate::Mode::Hashcat(40127)],
        64 => vec![crate::Mode::Hashcat(40128)],
        _ => Vec::new(),
    }
}

impl Parse for CubeHash {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let digest = parse::decode_hex(input, 0)?;
        if !matches!(digest.len(), 28 | 32 | 48 | 64) {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                0,
                "CubeHash digests have an unsupported length",
            ));
        }
        Ok(Self { digest })
    }
}

impl Render for CubeHash {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::hex(&self.digest)
    }
}
