//! SHA3, rendered as a bare hexadecimal digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// A single SHA3 digest.
///
/// The output size is selected by the hashcat mode; the serialized hash is
/// the digest alone.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "SHA3",
    slug = "sha3",
    hashcat = [17300, 17400, 17500, 17600],
    john = ["Raw-SHA3"],
    modes_fn = sha3_modes,
)]
pub struct Sha3 {
    /// Digest (variable length)
    #[field(role = digest, encoding = hex)]
    pub digest: Vec<u8>,
}

pub fn sha3_modes(value: &Sha3) -> Vec<crate::Mode> {
    match value.digest.len() {
        28 => vec![crate::Mode::Hashcat(17300)],
        32 => vec![crate::Mode::Hashcat(17400)],
        48 => vec![crate::Mode::Hashcat(17500)],
        64 => vec![crate::Mode::Hashcat(17600), crate::Mode::John("Raw-SHA3")],
        _ => Vec::new(),
    }
}

impl Parse for Sha3 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let digest = parse::decode_hex(input, 0)?;
        if !matches!(digest.len(), 28 | 32 | 48 | 64) {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                0,
                "SHA3 digests have an unsupported length",
            ));
        }
        Ok(Self { digest })
    }
}

impl Render for Sha3 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::hex(&self.digest)
    }
}
