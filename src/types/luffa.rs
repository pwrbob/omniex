//! Luffa, rendered as a bare hexadecimal digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// A single Luffa digest.
///
/// The output size is selected by the hashcat mode; the serialized hash is
/// the digest alone.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Luffa",
    slug = "luffa",
    hashcat = [40149, 40150, 40151, 40152],
    modes_fn = luffa_modes,
)]
pub struct Luffa {
    /// The digest, whose length selects the Luffa output size.
    #[field(role = digest, encoding = hex)]
    pub digest: Vec<u8>,
}

pub fn luffa_modes(value: &Luffa) -> Vec<crate::Mode> {
    match value.digest.len() {
        28 => vec![crate::Mode::Hashcat(40149)],
        32 => vec![crate::Mode::Hashcat(40150)],
        48 => vec![crate::Mode::Hashcat(40151)],
        64 => vec![crate::Mode::Hashcat(40152)],
        _ => Vec::new(),
    }
}

impl Parse for Luffa {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let digest = parse::decode_hex(input, 0)?;
        if !matches!(digest.len(), 28 | 32 | 48 | 64) {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                0,
                "Luffa digests have an unsupported length",
            ));
        }
        Ok(Self { digest })
    }
}

impl Render for Luffa {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::hex(&self.digest)
    }
}
