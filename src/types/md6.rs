//! MD6, rendered as a bare hexadecimal digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// A single MD6 digest.
///
/// The output size is selected by the hashcat mode; the serialized hash is
/// the digest alone.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "MD6",
    slug = "md6",
    hashcat = [40168, 40170, 34600],
    modes_fn = md6_modes,
)]
pub struct Md6 {
    /// The digest, whose length selects the MD6 output size.
    #[field(role = digest, encoding = hex)]
    pub digest: Vec<u8>,
}

pub fn md6_modes(value: &Md6) -> Vec<crate::Mode> {
    match value.digest.len() {
        16 => vec![crate::Mode::Hashcat(40168)],
        32 => vec![crate::Mode::Hashcat(34600)],
        64 => vec![crate::Mode::Hashcat(40170)],
        _ => Vec::new(),
    }
}

impl Parse for Md6 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let digest = parse::decode_hex(input, 0)?;
        if !matches!(digest.len(), 16 | 32 | 64) {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                0,
                "MD6 digests have an unsupported length",
            ));
        }
        Ok(Self { digest })
    }
}

impl Render for Md6 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::hex(&self.digest)
    }
}
