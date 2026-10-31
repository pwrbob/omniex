//! WinZip AES hashes, rendered as
//! `$zip2$*<type>*<mode>*<magic>*<salt>*<verify bytes>*<compressed length>*<data>*<checksum>*$/zip2$`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// WinZip AES hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "WinZip", slug = "winzip", hashcat = [13600])]
pub struct WinZip {
    /// Encryption type, always `0`.
    #[field(role = other, encoding = decimal)]
    pub kind: u8,

    /// AES strength mode.
    #[field(role = other, encoding = decimal)]
    pub mode: u8,

    /// Magic marker, always `0`.
    #[field(role = other, encoding = decimal)]
    pub magic: u8,

    /// Hexadecimal salt.
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// Password verification bytes.
    #[field(role = other, encoding = ascii)]
    pub verify_bytes: String,

    /// Compressed data length in hex.
    #[field(role = other, encoding = ascii)]
    pub compressed_length: String,

    /// Compressed data.
    #[field(role = ciphertext, encoding = ascii)]
    pub data: String,

    /// Authentication checksum.
    #[field(role = digest, encoding = ascii)]
    pub checksum: String,
}

impl Parse for WinZip {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$zip2$*", 0)?;
        let rest = rest.strip_suffix("*$/zip2$").ok_or_else(|| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                input.len(),
                "expected suffix `*$/zip2$`",
            )
        })?;
        let fields = parse::split_fields(rest, '*', 8)?;
        let number = |field: (&str, usize), name: &str| -> Result<u8, ParseError> {
            field.0.parse::<u8>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    field.1,
                    format!("invalid WinZip {name}"),
                )
            })
        };
        Ok(Self {
            kind: number(fields[0], "type")?,
            mode: number(fields[1], "mode")?,
            magic: number(fields[2], "magic")?,
            salt: fields[3].0.to_owned(),
            verify_bytes: fields[4].0.to_owned(),
            compressed_length: fields[5].0.to_owned(),
            data: fields[6].0.to_owned(),
            checksum: fields[7].0.to_owned(),
        })
    }
}

impl Render for WinZip {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$zip2$*{}*{}*{}*{}*{}*{}*{}*{}*$/zip2$",
            self.kind,
            self.mode,
            self.magic,
            self.salt,
            self.verify_bytes,
            self.compressed_length,
            self.data,
            self.checksum
        )
    }
}
