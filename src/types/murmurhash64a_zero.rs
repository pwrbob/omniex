//! MurmurHash64A with a zero seed, rendered as a bare hexadecimal digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// MurmurHash64A values computed with a zero seed.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "MurmurHash64A (zero seed)",
    slug = "murmurhash64a-zero",
    hashcat = [34201, 34211],
    modes_fn = murmurhash64a_zero_modes,
)]
pub struct MurmurHash64aZero {
    /// The digest, whose length selects the truncation.
    #[field(role = digest, encoding = hex)]
    pub digest: Vec<u8>,
}

pub fn murmurhash64a_zero_modes(value: &MurmurHash64aZero) -> Vec<crate::Mode> {
    match value.digest.len() {
        8 => vec![crate::Mode::Hashcat(34201)],
        4 => vec![crate::Mode::Hashcat(34211)],
        _ => Vec::new(),
    }
}

impl Parse for MurmurHash64aZero {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let digest = parse::decode_hex(input, 0)?;
        if !matches!(digest.len(), 4 | 8) {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                0,
                "zero-seed MurmurHash64A digests are 4 or 8 bytes",
            ));
        }
        Ok(Self { digest })
    }
}

impl Render for MurmurHash64aZero {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::hex(&self.digest)
    }
}
