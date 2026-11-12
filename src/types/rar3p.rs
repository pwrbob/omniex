//! RAR3-p, rendered as a `$RAR3$` field sequence.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// RAR3 packed-file hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "RAR3-p",
    slug = "rar3p",
    hashcat = [23700, 23800],
)]
pub struct Rar3p {
    /// Header type
    #[field(role = other, encoding = ascii)]
    pub header_type: String,

    /// 8-byte salt
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 8],

    /// 4-byte CRC
    #[field(role = other, encoding = hex)]
    pub crc: [u8; 4],

    /// Packed size
    #[field(role = other, encoding = decimal)]
    pub pack_size: u32,

    /// Unpacked size
    #[field(role = other, encoding = decimal)]
    pub unpack_size: u32,

    /// Compression method
    #[field(role = other, encoding = decimal)]
    pub method: u8,

    /// Data
    #[field(role = ciphertext, encoding = hex)]
    pub data: Vec<u8>,

    /// Final check byte
    #[field(role = digest, encoding = hex)]
    pub check: [u8; 1],
}

impl Parse for Rar3p {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$RAR3$*", 0)?;
        let fields = parse::split_fields(rest, '*', 8)?;
        Ok(Self {
            header_type: fields[0].0.to_owned(),
            salt: parse::decode_hex_field::<8>(fields[1].0, fields[1].1, "salt")?,
            crc: parse::decode_hex_field::<4>(fields[2].0, fields[2].1, "crc")?,
            pack_size: fields[3].0.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    fields[3].1,
                    "invalid RAR pack size",
                )
            })?,
            unpack_size: fields[4].0.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    fields[4].1,
                    "invalid RAR unpack size",
                )
            })?,
            method: fields[5].0.parse::<u8>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    fields[5].1,
                    "invalid RAR method",
                )
            })?,
            data: parse::decode_hex(fields[6].0, fields[6].1)?,
            check: parse::decode_hex_field::<1>(fields[7].0, fields[7].1, "check")?,
        })
    }
}

impl Render for Rar3p {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$RAR3$*{}*{}*{}*{}*{}*{}*{}*{}",
            self.header_type,
            crate::format::hex(self.salt),
            crate::format::hex(self.crc),
            self.pack_size,
            self.unpack_size,
            self.method,
            crate::format::hex(&self.data),
            crate::format::hex(self.check)
        )
    }
}
