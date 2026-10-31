//! JKS Java Key Store private key, rendered as a `$jksprivk$` field sequence.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// JKS Java Key Store private keys.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "JKS Java Key Store Private Keys (SHA1)",
    slug = "jks-private-key",
    hashcat = [15500],
)]
pub struct JksPrivateKey {
    /// Hexadecimal checksum.
    #[field(role = digest, encoding = hex)]
    pub checksum: [u8; 20],

    /// Hexadecimal IV.
    #[field(role = iv, encoding = hex)]
    pub iv: [u8; 20],

    /// Hexadecimal encrypted key.
    #[field(role = ciphertext, encoding = hex)]
    pub encrypted_key: Vec<u8>,

    /// First DER byte.
    #[field(role = other, encoding = hex)]
    pub der1: [u8; 1],

    /// Remaining DER bytes.
    #[field(role = other, encoding = hex)]
    pub der2: [u8; 14],

    /// Key alias.
    #[field(role = other, encoding = ascii)]
    pub alias: String,
}

impl Parse for JksPrivateKey {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$jksprivk$*", 0)?;
        let fields = parse::split_fields(rest, '*', 6)?;
        Ok(Self {
            checksum: parse::decode_hex_field::<20>(fields[0].0, fields[0].1, "checksum")?,
            iv: parse::decode_hex_field::<20>(fields[1].0, fields[1].1, "iv")?,
            encrypted_key: parse::decode_hex(fields[2].0, fields[2].1)?,
            der1: parse::decode_hex_field::<1>(fields[3].0, fields[3].1, "der1")?,
            der2: parse::decode_hex_field::<14>(fields[4].0, fields[4].1, "der2")?,
            alias: fields[5].0.to_owned(),
        })
    }
}

impl Render for JksPrivateKey {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$jksprivk$*{}*{}*{}*{}*{}*{}",
            crate::format::hex(self.checksum).to_uppercase(),
            crate::format::hex(self.iv).to_uppercase(),
            crate::format::hex(&self.encrypted_key).to_uppercase(),
            crate::format::hex(self.der1).to_uppercase(),
            crate::format::hex(self.der2).to_uppercase(),
            self.alias
        )
    }
}
