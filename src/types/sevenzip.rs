//! 7-Zip hashes, rendered as
//! `$7z$<data type>$<cycles power>$<salt length>$<salt>$<iv length>$<iv>$<crc>$<data length>$<unpacked length>$<data>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// 7-Zip archive hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "7-Zip", slug = "sevenzip", hashcat = [11600])]
pub struct SevenZip {
    /// Data type identifier.
    #[field(role = other, encoding = decimal)]
    pub data_type: u8,

    /// Base-2 logarithm of the cycle count.
    #[field(role = iterations, encoding = decimal)]
    pub cycles_power: u8,

    /// Salt size in bytes.
    #[field(role = other, encoding = decimal)]
    pub salt_size: u8,

    /// Hexadecimal salt.
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// Initialization vector size in bytes.
    #[field(role = other, encoding = decimal)]
    pub iv_size: u8,

    /// Hexadecimal initialization vector.
    #[field(role = other, encoding = ascii)]
    pub iv: String,

    /// CRC checksum.
    #[field(role = other, encoding = decimal)]
    pub crc: u32,

    /// Encrypted data length.
    #[field(role = other, encoding = decimal)]
    pub data_size: u32,

    /// Unpacked data length.
    #[field(role = other, encoding = decimal)]
    pub unpacked_size: u32,

    /// Encrypted data and optional trailing fields.
    #[field(role = ciphertext, encoding = ascii)]
    pub data: String,
}

impl Parse for SevenZip {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$7z$", 0)?;
        let fields = parse::split_fields(rest, '$', 10)?;
        fn number(value: &str, offset: usize, name: &str) -> Result<u32, ParseError> {
            value.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    offset,
                    format!("invalid 7-Zip {name}"),
                )
            })
        }
        fn small(value: &str, offset: usize, name: &str) -> Result<u8, ParseError> {
            u8::try_from(number(value, offset, name)?).map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    offset,
                    format!("invalid 7-Zip {name}"),
                )
            })
        }

        Ok(Self {
            data_type: small(fields[0].0, fields[0].1, "data type")?,
            cycles_power: small(fields[1].0, fields[1].1, "cycle power")?,
            salt_size: small(fields[2].0, fields[2].1, "salt size")?,
            salt: fields[3].0.to_owned(),
            iv_size: small(fields[4].0, fields[4].1, "iv size")?,
            iv: fields[5].0.to_owned(),
            crc: number(fields[6].0, fields[6].1, "crc")?,
            data_size: number(fields[7].0, fields[7].1, "data size")?,
            unpacked_size: number(fields[8].0, fields[8].1, "unpacked size")?,
            data: fields[9].0.to_owned(),
        })
    }
}

impl Render for SevenZip {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$7z${}${}${}${}${}${}${}${}${}${}",
            self.data_type,
            self.cycles_power,
            self.salt_size,
            self.salt,
            self.iv_size,
            self.iv,
            self.crc,
            self.data_size,
            self.unpacked_size,
            self.data
        )
    }
}
