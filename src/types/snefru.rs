//! Snefru, rendered as a bare hexadecimal digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// A single Snefru digest.
///
/// The output size is selected by the hashcat mode; the serialized hash is
/// the digest alone.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Snefru",
    slug = "snefru",
    hashcat = [40094, 40095], john = ["Snefru-128", "Snefru-256"],
    modes_fn = snefru_modes,
)]
pub struct Snefru {
    /// Digest (variable length)
    #[field(role = digest, encoding = hex)]
    pub digest: Vec<u8>,
}

pub fn snefru_modes(value: &Snefru) -> Vec<crate::Mode> {
    match value.digest.len() {
        16 => vec![crate::Mode::Hashcat(40094)],
        32 => vec![crate::Mode::Hashcat(40095)],
        _ => Vec::new(),
    }
}

impl Parse for Snefru {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let digest = match input.strip_prefix("$snefru$") {
            Some(rest) => parse::decode_hex(rest, 8)?,
            None => parse::decode_hex(input, 0)?,
        };
        if !matches!(digest.len(), 16 | 32) {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                0,
                "Snefru digests have an unsupported length",
            ));
        }
        Ok(Self { digest })
    }
}

impl Render for Snefru {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::hex(&self.digest)
    }
}
