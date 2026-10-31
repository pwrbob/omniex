//! MIFARE Ultralight C key recovery hashes, rendered as a `$mfulc$` field sequence.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// MIFARE Ultralight C 3DES key recovery hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "MIFARE Ultralight C", slug = "mifare", hashcat = [37000])]
pub struct Mifare {
    /// Format version.
    #[field(role = other, encoding = decimal)]
    pub version: u8,

    /// Key type.
    #[field(role = other, encoding = decimal)]
    pub key_type: u8,

    /// Sector number.
    #[field(role = other, encoding = decimal)]
    pub sector: u8,

    /// Eight-byte UID.
    #[field(role = other, encoding = hex)]
    pub uid: [u8; 8],

    /// Eight-byte key.
    #[field(role = key, encoding = hex)]
    pub key: [u8; 8],

    /// Eight-byte MAC.
    #[field(role = digest, encoding = hex)]
    pub mac: [u8; 8],

    /// Sixteen bytes of card data.
    #[field(role = ciphertext, encoding = hex)]
    pub data: [u8; 16],
}

impl Parse for Mifare {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$mfulc$", 0)?;
        let fields = parse::split_fields(rest, '$', 7)?;
        fn number(value: &str, offset: usize, name: &str) -> Result<u8, ParseError> {
            value.parse::<u8>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    offset,
                    format!("invalid MIFARE {name}"),
                )
            })
        }
        Ok(Self {
            version: number(fields[0].0, fields[0].1, "version")?,
            key_type: number(fields[1].0, fields[1].1, "key type")?,
            sector: number(fields[2].0, fields[2].1, "sector")?,
            uid: parse::decode_hex_field::<8>(fields[3].0, fields[3].1, "uid")?,
            key: parse::decode_hex_field::<8>(fields[4].0, fields[4].1, "key")?,
            mac: parse::decode_hex_field::<8>(fields[5].0, fields[5].1, "mac")?,
            data: parse::decode_hex_field::<16>(fields[6].0, fields[6].1, "data")?,
        })
    }
}

impl Render for Mifare {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$mfulc${}${}${}${}${}${}${}",
            self.version,
            self.key_type,
            self.sector,
            crate::format::hex(self.uid),
            crate::format::hex(self.key),
            crate::format::hex(self.mac),
            crate::format::hex(self.data)
        )
    }
}
