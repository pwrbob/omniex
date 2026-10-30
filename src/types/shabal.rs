//! Shabal, rendered as a bare hexadecimal digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// A single Shabal digest.
///
/// The output size is selected by the hashcat mode; the serialized hash is
/// the digest alone.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Shabal",
    slug = "shabal",
    hashcat = [40153, 40154, 40155, 40156],
    modes_fn = shabal_modes,
)]
pub struct Shabal {
    /// The digest, whose length selects the Shabal output size.
    #[field(role = digest, encoding = hex)]
    pub digest: Vec<u8>,
}

pub fn shabal_modes(value: &Shabal) -> Vec<crate::Mode> {
    match value.digest.len() {
        28 => vec![crate::Mode::Hashcat(40153)],
        32 => vec![crate::Mode::Hashcat(40154)],
        48 => vec![crate::Mode::Hashcat(40155)],
        64 => vec![crate::Mode::Hashcat(40156)],
        _ => Vec::new(),
    }
}

impl Parse for Shabal {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let digest = parse::decode_hex(input, 0)?;
        if !matches!(digest.len(), 28 | 32 | 48 | 64) {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                0,
                "Shabal digests have an unsupported length",
            ));
        }
        Ok(Self { digest })
    }
}

impl Render for Shabal {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::hex(&self.digest)
    }
}
