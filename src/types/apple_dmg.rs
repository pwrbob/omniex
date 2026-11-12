//! Apple DMG hashes, rendered as
//! `$dmg$3*<salt size>*<salt>*<key bits>*<blob size>*<key blob>*<iterations>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Apple DMG (encrcdsa v2) hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "Apple DMG", slug = "apple-dmg", hashcat = [38300])]
pub struct AppleDmg {
    /// Salt size in bytes
    #[field(role = other, encoding = decimal)]
    pub salt_size: u8,

    /// 20-byte salt
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 20],

    /// AES key size in bits
    #[field(role = other, encoding = decimal)]
    pub key_bits: u16,

    /// Key blob size in bytes
    #[field(role = other, encoding = decimal)]
    pub blob_size: u8,

    /// 64-byte key blob
    #[field(role = ciphertext, encoding = hex)]
    pub key_blob: [u8; 64],

    /// PBKDF2 iteration count
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,
}

impl Parse for AppleDmg {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$dmg$3*", 0)?;
        let fields = parse::split_fields(rest, '*', 6)?;
        let number = |field: (&str, usize), name: &str| -> Result<u32, ParseError> {
            field.0.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    field.1,
                    format!("invalid DMG {name}"),
                )
            })
        };
        Ok(Self {
            salt_size: u8::try_from(number(fields[0], "salt size")?).map_err(|_| {
                parse::error(ParseErrorKind::InvalidCharacter, 7, "invalid salt size")
            })?,
            salt: parse::decode_hex_field::<20>(fields[1].0, fields[1].1, "salt")?,
            key_bits: u16::try_from(number(fields[2], "key bits")?).map_err(|_| {
                parse::error(ParseErrorKind::InvalidCharacter, 9, "invalid key size")
            })?,
            blob_size: u8::try_from(number(fields[3], "blob size")?).map_err(|_| {
                parse::error(ParseErrorKind::InvalidCharacter, 11, "invalid blob size")
            })?,
            key_blob: parse::decode_hex_field::<64>(fields[4].0, fields[4].1, "key blob")?,
            iterations: number(fields[5], "iterations")?,
        })
    }
}

impl Render for AppleDmg {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$dmg$3*{}*{}*{}*{}*{}*{}",
            self.salt_size,
            crate::format::hex(self.salt),
            self.key_bits,
            self.blob_size,
            crate::format::hex(self.key_blob),
            self.iterations
        )
    }
}
