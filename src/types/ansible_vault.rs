//! Ansible Vault, rendered as `$ansible$<version>*<cipher>*<salt>*<ciphertext>*<hmac>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Ansible Vault encrypted values.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Ansible Vault",
    slug = "ansible-vault",
    hashcat = [16900],
)]
pub struct AnsibleVault {
    /// Vault format version.
    #[field(role = other, encoding = decimal)]
    pub version: u8,

    /// Vault cipher identifier.
    #[field(role = other, encoding = decimal)]
    pub cipher: u8,

    /// The 32-byte salt.
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 32],

    /// Hexadecimal ciphertext.
    #[field(role = ciphertext, encoding = hex)]
    pub ciphertext: Vec<u8>,

    /// The 32-byte HMAC.
    #[field(role = digest, encoding = hex)]
    pub hmac: [u8; 32],
}

impl Parse for AnsibleVault {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$ansible$", 0)?;
        let fields = parse::split_fields(rest, '*', 5)?;
        Ok(Self {
            version: fields[0].0.parse::<u8>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    9,
                    "invalid Ansible Vault version",
                )
            })?,
            cipher: fields[1].0.parse::<u8>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    fields[1].1,
                    "invalid Ansible Vault cipher",
                )
            })?,
            salt: parse::decode_hex_field::<32>(fields[2].0, fields[2].1, "salt")?,
            ciphertext: parse::decode_hex(fields[3].0, fields[3].1)?,
            hmac: parse::decode_hex_field::<32>(fields[4].0, fields[4].1, "hmac")?,
        })
    }
}

impl Render for AnsibleVault {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$ansible${}*{}*{}*{}*{}",
            self.version,
            self.cipher,
            crate::format::hex(self.salt),
            crate::format::hex(&self.ciphertext),
            crate::format::hex(self.hmac)
        )
    }
}
