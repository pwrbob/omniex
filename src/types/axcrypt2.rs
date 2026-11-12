//! AxCrypt 2, rendered as `$axcrypt$*<version>*<iterations>*<key>*<data>*<iterations>*<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// AxCrypt 2 encrypted files.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "AxCrypt 2",
    slug = "axcrypt2",
    hashcat = [23500, 23600],
    john = ["axcrypt2-opencl"],
)]
pub struct Axcrypt2 {
    /// Format version
    #[field(role = other, encoding = decimal)]
    pub version: u8,

    /// Iteration count
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// Key block
    #[field(role = key, encoding = hex)]
    pub key: Vec<u8>,

    /// Encrypted data
    #[field(role = ciphertext, encoding = hex)]
    pub data: Vec<u8>,

    /// Second iteration count
    #[field(role = iterations, encoding = decimal)]
    pub second_iterations: u32,

    /// Digest
    #[field(role = digest, encoding = hex)]
    pub digest: Vec<u8>,
}

impl Parse for Axcrypt2 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$axcrypt$*", 0)?;
        let fields = parse::split_fields(rest, '*', 6)?;
        Ok(Self {
            version: fields[0].0.parse::<u8>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    10,
                    "invalid AxCrypt version",
                )
            })?,
            iterations: fields[1].0.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    fields[1].1,
                    "invalid AxCrypt iteration count",
                )
            })?,
            key: parse::decode_hex(fields[2].0, fields[2].1)?,
            data: parse::decode_hex(fields[3].0, fields[3].1)?,
            second_iterations: fields[4].0.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    fields[4].1,
                    "invalid AxCrypt second iteration count",
                )
            })?,
            digest: parse::decode_hex(fields[5].0, fields[5].1)?,
        })
    }
}

impl Render for Axcrypt2 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$axcrypt$*{}*{}*{}*{}*{}*{}",
            self.version,
            self.iterations,
            crate::format::hex(&self.key),
            crate::format::hex(&self.data),
            self.second_iterations,
            crate::format::hex(&self.digest)
        )
    }
}
