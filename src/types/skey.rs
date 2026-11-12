//! S/Key hashes, rendered as `<iteration> <seed> <digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// S/Key hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "S/Key", slug = "skey", hashcat = [], john = ["skey"])]
pub struct Skey {
    /// Iteration number
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// Seed value
    #[field(role = salt, encoding = ascii)]
    pub seed: String,

    /// 8-byte digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 8],
}

impl Parse for Skey {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let fields = input.split_whitespace().collect::<Vec<_>>();
        if fields.len() != 3 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                input.len(),
                "S/Key hashes have three fields",
            ));
        }
        Ok(Self {
            iterations: fields[0].parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    0,
                    "invalid S/Key iteration",
                )
            })?,
            seed: fields[1].to_owned(),
            digest: parse::decode_hex_field::<8>(fields[2], 0, "digest")?,
        })
    }
}

impl Render for Skey {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "{:04} {}  {}",
            self.iterations,
            self.seed,
            crate::format::hex(self.digest)
        )
    }
}
