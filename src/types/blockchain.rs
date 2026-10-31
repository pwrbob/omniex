//! Blockchain wallet, rendered as `$blockchain$[v2$]<iterations>$<length>$<data>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Blockchain wallet hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Blockchain, My Wallet",
    slug = "blockchain",
    hashcat = [12700, 15200], john = ["Blockchain"],
    modes_fn = blockchain_modes,
)]
pub struct Blockchain {
    /// Serialization version, either `1` or `v2`.
    #[field(role = other, encoding = ascii)]
    pub version: String,

    /// Iteration count.
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// Data length.
    #[field(role = other, encoding = decimal)]
    pub length: u32,

    /// Hexadecimal data.
    #[field(role = ciphertext, encoding = hex)]
    pub data: Vec<u8>,
}

pub fn blockchain_modes(value: &Blockchain) -> Vec<crate::Mode> {
    if value.version == "v2" {
        vec![crate::Mode::Hashcat(15200)]
    } else {
        vec![crate::Mode::Hashcat(12700)]
    }
}

impl Parse for Blockchain {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$blockchain$", 0)?;
        if let Some(rest) = rest.strip_prefix("v2$") {
            let fields = parse::split_fields(rest, '$', 3)?;
            return Ok(Self {
                version: "v2".to_owned(),
                iterations: fields[0].0.parse::<u32>().map_err(|_| {
                    parse::error(
                        ParseErrorKind::InvalidCharacter,
                        fields[0].1,
                        "invalid Blockchain iteration count",
                    )
                })?,
                length: fields[1].0.parse::<u32>().map_err(|_| {
                    parse::error(
                        ParseErrorKind::InvalidCharacter,
                        fields[1].1,
                        "invalid Blockchain data length",
                    )
                })?,
                data: parse::decode_hex(fields[2].0, fields[2].1)?,
            });
        }
        let fields = parse::split_fields(rest, '$', 2)?;
        let data = parse::decode_hex(fields[1].0, fields[1].1)?;
        Ok(Self {
            version: "1".to_owned(),
            iterations: fields[0].0.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    fields[0].1,
                    "invalid Blockchain iteration count",
                )
            })?,
            length: data.len() as u32,
            data,
        })
    }
}

impl Render for Blockchain {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        if self.version == "v2" {
            format!(
                "$blockchain$v2${}${}${}",
                self.iterations,
                self.length,
                crate::format::hex(&self.data)
            )
        } else {
            format!(
                "$blockchain${}${}",
                self.iterations,
                crate::format::hex(&self.data)
            )
        }
    }
}
