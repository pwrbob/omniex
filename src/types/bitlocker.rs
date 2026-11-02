//! BitLocker recovery key hashes, rendered as
//! `$bitlocker$<type>$<salt size>$<salt>$<iterations>$<nonce size>$<nonce>$<data size>$<data>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// BitLocker recovery key hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "BitLocker",
    slug = "bitlocker",
    hashcat = [22100],
    john = ["BitLocker"],
    modes_fn = bitlocker_modes
)]
pub struct BitLocker {
    /// Verification type, always `1`.
    #[field(role = other, encoding = decimal)]
    pub kind: u8,

    /// Salt size in bytes.
    #[field(role = other, encoding = decimal)]
    pub salt_size: u8,

    /// Sixteen-byte salt.
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 16],

    /// Key derivation iteration count.
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// Nonce size in bytes.
    #[field(role = other, encoding = decimal)]
    pub nonce_size: u8,

    /// Twelve-byte nonce.
    #[field(role = other, encoding = hex)]
    pub nonce: [u8; 12],

    /// Encrypted data size in bytes.
    #[field(role = other, encoding = decimal)]
    pub data_size: u8,

    /// Sixty-byte encrypted data.
    #[field(role = ciphertext, encoding = hex)]
    pub data: [u8; 60],
}

pub fn bitlocker_modes(value: &BitLocker) -> Vec<crate::Mode> {
    if value.kind == 1 {
        vec![crate::Mode::Hashcat(22100), crate::Mode::John("BitLocker")]
    } else {
        vec![crate::Mode::John("BitLocker")]
    }
}

impl Parse for BitLocker {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$bitlocker$", 0)?;
        let fields = parse::split_fields(rest, '$', 8)?;
        fn number(value: &str, offset: usize, name: &str) -> Result<u32, ParseError> {
            value.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    offset,
                    format!("invalid BitLocker {name}"),
                )
            })
        }
        fn small(value: &str, offset: usize, name: &str) -> Result<u8, ParseError> {
            u8::try_from(number(value, offset, name)?).map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    offset,
                    format!("invalid BitLocker {name}"),
                )
            })
        }
        Ok(Self {
            kind: small(fields[0].0, fields[0].1, "type")?,
            salt_size: small(fields[1].0, fields[1].1, "salt size")?,
            salt: parse::decode_hex_field::<16>(fields[2].0, fields[2].1, "salt")?,
            iterations: number(fields[3].0, fields[3].1, "iterations")?,
            nonce_size: small(fields[4].0, fields[4].1, "nonce size")?,
            nonce: parse::decode_hex_field::<12>(fields[5].0, fields[5].1, "nonce")?,
            data_size: small(fields[6].0, fields[6].1, "data size")?,
            data: parse::decode_hex_field::<60>(fields[7].0, fields[7].1, "data")?,
        })
    }
}

impl Render for BitLocker {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$bitlocker${}${}${}${}${}${}${}${}",
            self.kind,
            self.salt_size,
            crate::format::hex(self.salt),
            self.iterations,
            self.nonce_size,
            crate::format::hex(self.nonce),
            self.data_size,
            crate::format::hex(self.data)
        )
    }
}
