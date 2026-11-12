//! Microsoft SNTP hashes, rendered as `$sntp-ms$<digest>$<data>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// Microsoft SNTP hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "MS SNTP", slug = "sntp-ms", hashcat = [31300], john = ["timeroast"])]
pub struct SntpMs {
    /// 16-byte digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 16],

    /// Packet data
    #[field(role = ciphertext, encoding = hex)]
    pub data: Vec<u8>,
}

impl Parse for SntpMs {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$sntp-ms$", 0)?;
        let (digest, data, data_offset) = parse::split_once(rest, '$', 9)?;
        Ok(Self {
            digest: parse::decode_hex_field::<16>(digest, 9, "digest")?,
            data: parse::decode_hex(data, data_offset)?,
        })
    }
}

impl Render for SntpMs {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$sntp-ms${}${}",
            crate::format::hex(self.digest),
            crate::format::hex(&self.data)
        )
    }
}
