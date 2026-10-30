//! Hamsi, rendered as a bare hexadecimal digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// A single Hamsi digest.
///
/// The output size is selected by the hashcat mode; the serialized hash is
/// the digest alone.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Hamsi",
    slug = "hamsi",
    hashcat = [40141, 40142, 40143, 40144],
    modes_fn = hamsi_modes,
)]
pub struct Hamsi {
    /// The digest, whose length selects the Hamsi output size.
    #[field(role = digest, encoding = hex)]
    pub digest: Vec<u8>,
}

pub fn hamsi_modes(value: &Hamsi) -> Vec<crate::Mode> {
    match value.digest.len() {
        28 => vec![crate::Mode::Hashcat(40141)],
        32 => vec![crate::Mode::Hashcat(40142)],
        48 => vec![crate::Mode::Hashcat(40143)],
        64 => vec![crate::Mode::Hashcat(40144)],
        _ => Vec::new(),
    }
}

impl Parse for Hamsi {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let digest = parse::decode_hex(input, 0)?;
        if !matches!(digest.len(), 28 | 32 | 48 | 64) {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                0,
                "Hamsi digests have an unsupported length",
            ));
        }
        Ok(Self { digest })
    }
}

impl Render for Hamsi {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::hex(&self.digest)
    }
}
