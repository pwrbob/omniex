//! Mozilla key4.db, rendered as `$mozilla$*<cipher>*<salt>*<iv>*<iterations>*<iv2>*<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Mozilla key4.db hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Mozilla key4.db",
    slug = "mozilla-key4",
    hashcat = [26100, 26150],
    modes_fn = mozilla_key4_modes,
)]
pub struct MozillaKey4 {
    /// Cipher name.
    #[field(role = other, encoding = ascii)]
    pub cipher: String,

    /// Hexadecimal global salt.
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// Hexadecimal IV or entry salt.
    #[field(role = salt, encoding = ascii)]
    pub entry_salt: String,

    /// Iteration count.
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// Hexadecimal IV.
    #[field(role = iv, encoding = ascii)]
    pub iv: String,

    /// Hexadecimal digest.
    #[field(role = digest, encoding = hex)]
    pub digest: Vec<u8>,
}

pub fn mozilla_key4_modes(value: &MozillaKey4) -> Vec<crate::Mode> {
    if value.salt.len() == 96 {
        vec![crate::Mode::Hashcat(26150)]
    } else {
        vec![crate::Mode::Hashcat(26100)]
    }
}

impl Parse for MozillaKey4 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$mozilla$*", 0)?;
        let fields = parse::split_fields(rest, '*', 6)?;
        Ok(Self {
            cipher: fields[0].0.to_owned(),
            salt: fields[1].0.to_owned(),
            entry_salt: fields[2].0.to_owned(),
            iterations: fields[3].0.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    fields[3].1,
                    "invalid Mozilla iteration count",
                )
            })?,
            iv: fields[4].0.to_owned(),
            digest: parse::decode_hex(fields[5].0, fields[5].1)?,
        })
    }
}

impl Render for MozillaKey4 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$mozilla$*{}*{}*{}*{}*{}*{}",
            self.cipher,
            self.salt,
            self.entry_salt,
            self.iterations,
            self.iv,
            crate::format::hex(&self.digest)
        )
    }
}
