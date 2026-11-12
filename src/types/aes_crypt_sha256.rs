//! AES Crypt with SHA2-256, rendered as `$aescrypt$<version>*<salt>*<iv>*<ciphertext>*<hmac>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// AES Crypt with SHA2-256 key derivation.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "AES Crypt (SHA256)",
    slug = "aes-crypt-sha256",
    hashcat = [22400],
)]
pub struct AesCryptSha256 {
    /// Format version
    #[field(role = other, encoding = decimal)]
    pub version: u8,

    /// 16-byte salt
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 16],

    /// 16-byte IV
    #[field(role = iv, encoding = hex)]
    pub iv: [u8; 16],

    /// 32-byte ciphertext
    #[field(role = ciphertext, encoding = hex)]
    pub ciphertext: [u8; 32],

    /// 32-byte HMAC
    #[field(role = digest, encoding = hex)]
    pub hmac: [u8; 32],
}

impl Parse for AesCryptSha256 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$aescrypt$", 0)?;
        let fields = parse::split_fields(rest, '*', 5)?;
        Ok(Self {
            version: fields[0].0.parse::<u8>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    10,
                    "invalid AES Crypt version",
                )
            })?,
            salt: parse::decode_hex_field::<16>(fields[1].0, fields[1].1, "salt")?,
            iv: parse::decode_hex_field::<16>(fields[2].0, fields[2].1, "iv")?,
            ciphertext: parse::decode_hex_field::<32>(fields[3].0, fields[3].1, "ciphertext")?,
            hmac: parse::decode_hex_field::<32>(fields[4].0, fields[4].1, "hmac")?,
        })
    }
}

impl Render for AesCryptSha256 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$aescrypt${}*{}*{}*{}*{}",
            self.version,
            crate::format::hex(self.salt),
            crate::format::hex(self.iv),
            crate::format::hex(self.ciphertext),
            crate::format::hex(self.hmac)
        )
    }
}
