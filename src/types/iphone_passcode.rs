//! iPhone passcode hashes, rendered as `$uido$<uid key>$<salt>$<iterations>$<class key>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// iPhone UID-key and System Keybag passcode hash.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "iPhone passcode",
    slug = "iphone-passcode",
    hashcat = [26500],
)]
pub struct IphonePasscode {
    /// Sixteen-byte UID key.
    #[field(role = key, encoding = hex)]
    pub uid_key: [u8; 16],

    /// Twenty-byte PBKDF2 salt.
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 20],

    /// PBKDF2 iteration count.
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// Forty-byte class key.
    #[field(role = ciphertext, encoding = hex)]
    pub class_key: [u8; 40],
}

impl Parse for IphonePasscode {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$uido$", 0)?;
        let fields = parse::split_fields(rest, '$', 4)?;
        Ok(Self {
            uid_key: parse::decode_hex_field::<16>(fields[0].0, fields[0].1, "UID key")?,
            salt: parse::decode_hex_field::<20>(fields[1].0, fields[1].1, "salt")?,
            iterations: fields[2].0.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    fields[2].1,
                    "invalid iPhone PBKDF2 iteration count",
                )
            })?,
            class_key: parse::decode_hex_field::<40>(fields[3].0, fields[3].1, "class key")?,
        })
    }
}

impl Render for IphonePasscode {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$uido${}${}${}${}",
            crate::format::hex(self.uid_key),
            crate::format::hex(self.salt),
            self.iterations,
            crate::format::hex(self.class_key)
        )
    }
}
