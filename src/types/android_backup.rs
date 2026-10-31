//! Android Backup encryption hashes, rendered as
//! `$ab$<version>*<cipher>*<iterations>*<user salt>*<checksum salt>*<user iv>*<master key blob>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Android Backup encryption hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "Android Backup", slug = "android-backup", hashcat = [18900])]
pub struct AndroidBackup {
    /// Backup format version.
    #[field(role = other, encoding = decimal)]
    pub version: u8,

    /// Cipher identifier.
    #[field(role = other, encoding = decimal)]
    pub cipher: u8,

    /// Key derivation iteration count.
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// Sixty-four-byte user salt.
    #[field(role = salt, encoding = hex)]
    pub user_salt: [u8; 64],

    /// Sixty-four-byte checksum salt.
    #[field(role = other, encoding = hex)]
    pub checksum_salt: [u8; 64],

    /// Sixteen-byte user initialization vector.
    #[field(role = other, encoding = hex)]
    pub user_iv: [u8; 16],

    /// Ninety-six-byte master key blob.
    #[field(role = ciphertext, encoding = hex)]
    pub master_key_blob: [u8; 96],
}

impl Parse for AndroidBackup {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$ab$", 0)?;
        let fields = parse::split_fields(rest, '*', 7)?;
        let number = |field: (&str, usize), name: &str| -> Result<u8, ParseError> {
            field.0.parse::<u8>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    field.1,
                    format!("invalid Android backup {name}"),
                )
            })
        };
        let iterations = fields[2].0.parse::<u32>().map_err(|_| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                fields[2].1,
                "invalid Android backup iteration count",
            )
        })?;
        Ok(Self {
            version: number(fields[0], "version")?,
            cipher: number(fields[1], "cipher")?,
            iterations,
            user_salt: parse::decode_hex_field::<64>(fields[3].0, fields[3].1, "user salt")?,
            checksum_salt: parse::decode_hex_field::<64>(
                fields[4].0,
                fields[4].1,
                "checksum salt",
            )?,
            user_iv: parse::decode_hex_field::<16>(fields[5].0, fields[5].1, "user iv")?,
            master_key_blob: parse::decode_hex_field::<96>(
                fields[6].0,
                fields[6].1,
                "master key blob",
            )?,
        })
    }
}

impl Render for AndroidBackup {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$ab${}*{}*{}*{}*{}*{}*{}",
            self.version,
            self.cipher,
            self.iterations,
            crate::format::hex(self.user_salt),
            crate::format::hex(self.checksum_salt),
            crate::format::hex(self.user_iv),
            crate::format::hex(self.master_key_blob)
        )
    }
}
