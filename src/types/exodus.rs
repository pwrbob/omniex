//! Exodus Desktop Wallet, rendered as `EXODUS:<n>:<r>:<p>:<salt>:<iv>:<ciphertext>:<mac>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Exodus Desktop Wallet hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Exodus Desktop Wallet (scrypt)",
    slug = "exodus",
    hashcat = [28200],
)]
pub struct Exodus {
    /// CPU/memory cost parameter
    #[field(role = iterations, encoding = decimal)]
    pub n: u32,

    /// Block size parameter
    #[field(role = other, encoding = decimal)]
    pub r: u32,

    /// Parallelization parameter
    #[field(role = other, encoding = decimal)]
    pub p: u32,

    /// Salt
    #[field(role = salt, encoding = base64)]
    pub salt: Vec<u8>,

    /// IV
    #[field(role = iv, encoding = base64)]
    pub iv: Vec<u8>,

    /// Ciphertext
    #[field(role = ciphertext, encoding = base64)]
    pub ciphertext: Vec<u8>,

    /// MAC
    #[field(role = digest, encoding = base64)]
    pub mac: Vec<u8>,
}

impl Parse for Exodus {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "EXODUS:", 0)?;
        let fields = parse::split_fields(rest, ':', 7)?;
        let number = |field: (&str, usize), name: &str| {
            field.0.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    field.1,
                    format!("invalid Exodus {name}"),
                )
            })
        };
        Ok(Self {
            n: number(fields[0], "cost")?,
            r: number(fields[1], "block size")?,
            p: number(fields[2], "parallelization")?,
            salt: parse::decode_base64(fields[3].0, fields[3].1)?,
            iv: parse::decode_base64(fields[4].0, fields[4].1)?,
            ciphertext: parse::decode_base64(fields[5].0, fields[5].1)?,
            mac: parse::decode_base64(fields[6].0, fields[6].1)?,
        })
    }
}

impl Render for Exodus {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "EXODUS:{}:{}:{}:{}:{}:{}:{}",
            self.n,
            self.r,
            self.p,
            crate::format::base64(&self.salt),
            crate::format::base64(&self.iv),
            crate::format::base64(&self.ciphertext),
            crate::format::base64(&self.mac)
        )
    }
}
