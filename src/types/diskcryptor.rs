//! DiskCryptor, rendered as `$diskcryptor$<version>*<hex data>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// DiskCryptor volume hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "DiskCryptor",
    slug = "diskcryptor",
    hashcat = [20011, 20012, 20013], john = ["diskcryptor", "diskcryptor-aes-opencl"],
)]
pub struct Diskcryptor {
    /// Format version
    #[field(role = other, encoding = decimal)]
    pub version: u8,

    /// Encrypted key data
    #[field(role = ciphertext, encoding = hex)]
    pub data: Vec<u8>,
}

impl Parse for Diskcryptor {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$diskcryptor$", 0)?;
        let (version, data, data_offset) = parse::split_once(rest, '*', 13)?;
        Ok(Self {
            version: version.parse::<u8>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    13,
                    "invalid DiskCryptor version",
                )
            })?,
            data: parse::decode_hex(data, data_offset)?,
        })
    }
}

impl Render for Diskcryptor {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$diskcryptor${}*{}",
            self.version,
            crate::format::hex(&self.data)
        )
    }
}
