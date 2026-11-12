//! PKCS#12, rendered as `$pkcs12$<version>$<iterations>$<salt length>$<salt>$<length>$<data>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// PKCS#12 (.pfx, .p12) hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "PKCS#12",
    slug = "pkcs12",
    hashcat = [24430, 24440],
    modes_fn = pkcs12_modes,
)]
pub struct Pkcs12 {
    /// HMAC version
    #[field(role = other, encoding = decimal)]
    pub version: u32,

    /// Iteration count
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// Salt length
    #[field(role = other, encoding = decimal)]
    pub salt_length: u32,

    /// Salt
    #[field(role = salt, encoding = hex)]
    pub salt: Vec<u8>,

    /// Data length
    #[field(role = other, encoding = decimal)]
    pub length: u32,

    /// Encrypted data
    #[field(role = ciphertext, encoding = hex)]
    pub data: Vec<u8>,

    /// MAC
    #[field(role = digest, encoding = hex)]
    pub mac: Vec<u8>,
}

pub fn pkcs12_modes(value: &Pkcs12) -> Vec<crate::Mode> {
    match value.version {
        1 => vec![crate::Mode::Hashcat(24430)],
        256 => vec![crate::Mode::Hashcat(24440)],
        _ => Vec::new(),
    }
}

impl Parse for Pkcs12 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$pkcs12$", 0)?;
        let fields = parse::split_fields(rest, '$', 7)?;
        Ok(Self {
            version: fields[0].0.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    8,
                    "invalid PKCS#12 version",
                )
            })?,
            iterations: fields[1].0.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    fields[1].1,
                    "invalid PKCS#12 iteration count",
                )
            })?,
            salt_length: fields[2].0.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    fields[2].1,
                    "invalid PKCS#12 salt length",
                )
            })?,
            salt: parse::decode_hex(fields[3].0, fields[3].1)?,
            length: fields[4].0.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    fields[4].1,
                    "invalid PKCS#12 data length",
                )
            })?,
            data: parse::decode_hex(fields[5].0, fields[5].1)?,
            mac: parse::decode_hex(fields[6].0, fields[6].1)?,
        })
    }
}

impl Render for Pkcs12 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$pkcs12${}${}${}${}${}${}${}",
            self.version,
            self.iterations,
            self.salt_length,
            crate::format::hex(&self.salt),
            self.length,
            crate::format::hex(&self.data),
            crate::format::hex(&self.mac)
        )
    }
}
