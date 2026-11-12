//! Dogechain wallet hashes, rendered as
//! `$dogechain$<type>*<iterations>*<data>*<salt>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Dogechain.info wallet hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "Dogechain.info Wallet", slug = "dogechain", hashcat = [32500])]
pub struct Dogechain {
    /// Wallet type, always `0`
    #[field(role = other, encoding = decimal)]
    pub kind: u8,

    /// Iteration count
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// Encrypted data
    #[field(role = ciphertext, encoding = base64)]
    pub data: Vec<u8>,

    /// Salt
    #[field(role = salt, encoding = base64)]
    pub salt: Vec<u8>,
}

impl Parse for Dogechain {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$dogechain$", 0)?;
        let fields = parse::split_fields(rest, '*', 4)?;
        let kind = fields[0].0.parse::<u8>().map_err(|_| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                fields[0].1,
                "invalid Dogechain type",
            )
        })?;
        let iterations = fields[1].0.parse::<u32>().map_err(|_| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                fields[1].1,
                "invalid Dogechain iteration count",
            )
        })?;
        Ok(Self {
            kind,
            iterations,
            data: parse::decode_base64(fields[2].0, fields[2].1)?,
            salt: parse::decode_base64(fields[3].0, fields[3].1)?,
        })
    }
}

impl Render for Dogechain {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$dogechain${}*{}*{}*{}",
            self.kind,
            self.iterations,
            crate::format::base64(&self.data),
            crate::format::base64(&self.salt)
        )
    }
}
