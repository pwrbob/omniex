//! ECHO, rendered as a bare hexadecimal digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// A single ECHO digest.
///
/// The output size is selected by the hashcat mode; the serialized hash is
/// the digest alone.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "ECHO",
    slug = "echo",
    hashcat = [40129, 40130, 40131, 40132],
    modes_fn = echo_modes,
)]
pub struct Echo {
    /// The digest, whose length selects the ECHO output size.
    #[field(role = digest, encoding = hex)]
    pub digest: Vec<u8>,
}

pub fn echo_modes(value: &Echo) -> Vec<crate::Mode> {
    match value.digest.len() {
        28 => vec![crate::Mode::Hashcat(40129)],
        32 => vec![crate::Mode::Hashcat(40130)],
        48 => vec![crate::Mode::Hashcat(40131)],
        64 => vec![crate::Mode::Hashcat(40132)],
        _ => Vec::new(),
    }
}

impl Parse for Echo {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let digest = parse::decode_hex(input, 0)?;
        if !matches!(digest.len(), 28 | 32 | 48 | 64) {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                0,
                "ECHO digests have an unsupported length",
            ));
        }
        Ok(Self { digest })
    }
}

impl Render for Echo {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::hex(&self.digest)
    }
}
