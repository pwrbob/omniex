//! HMAC, rendered as `<digest>:<key>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// An HMAC digest with one key or salt.
///
/// The underlying hash and output size are selected by the hashcat mode; the
/// serialized hash is the digest and the key.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "HMAC",
    slug = "hmac",
    hashcat = [50, 60, 150, 160, 40013, 40014, 1450, 1460, 40027, 40028, 40072, 40073, 40074, 1750, 1760, 40029, 40030],
    modes_fn = hmac_modes,
)]
pub struct Hmac {
    /// The digest, whose length selects the HMAC algorithm.
    #[field(role = digest, encoding = hex)]
    pub digest: Vec<u8>,

    /// HMAC key or salt, serialized as ASCII.
    #[field(role = key, encoding = ascii)]
    pub key: String,
}

pub fn hmac_modes(value: &Hmac) -> Vec<crate::Mode> {
    if value.key.len() > 256 {
        return Vec::new();
    }
    match value.digest.len() {
        16 => vec![crate::Mode::Hashcat(50), crate::Mode::Hashcat(60)],
        20 => vec![
            crate::Mode::Hashcat(150),
            crate::Mode::Hashcat(160),
            crate::Mode::Hashcat(40013),
            crate::Mode::Hashcat(40014),
        ],
        32 => vec![
            crate::Mode::Hashcat(1450),
            crate::Mode::Hashcat(1460),
            crate::Mode::Hashcat(40027),
            crate::Mode::Hashcat(40028),
            crate::Mode::Hashcat(40072),
        ],
        40 => vec![crate::Mode::Hashcat(40073), crate::Mode::Hashcat(40074)],
        64 => vec![
            crate::Mode::Hashcat(1750),
            crate::Mode::Hashcat(1760),
            crate::Mode::Hashcat(40029),
            crate::Mode::Hashcat(40030),
        ],
        _ => Vec::new(),
    }
}

impl Parse for Hmac {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let Some(separator) = input.find(':') else {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                input.len(),
                "expected `:` between digest and key",
            ));
        };
        let key = &input[separator + 1..];
        if key.contains(':') {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                separator + 1,
                "key must not contain `:`",
            ));
        }
        let digest = parse::decode_hex(&input[..separator], 0)?;
        if !matches!(digest.len(), 16 | 20 | 32 | 40 | 64) {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                0,
                "HMAC digests have an unsupported length",
            ));
        }
        Ok(Self {
            digest,
            key: key.to_owned(),
        })
    }
}

impl Render for Hmac {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("{}:{}", crate::format::hex(&self.digest), self.key)
    }
}
