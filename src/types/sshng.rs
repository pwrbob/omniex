//! OpenSSH private keys, rendered as
//! `$sshng$<cipher>$8$<iv>$<data length>$<data>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Encrypted OpenSSH and PEM private keys.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "OpenSSH private keys",
    slug = "sshng",
    hashcat = [22911, 22921, 22931, 22941, 22951, 36800],
    modes_fn = sshng_modes,
)]
pub struct Sshng {
    /// Cipher identifier, which selects the mode.
    #[field(role = other, encoding = decimal)]
    pub cipher: u8,

    /// Eight-byte initialization vector.
    #[field(role = salt, encoding = hex)]
    pub iv: Vec<u8>,

    /// Encrypted key data.
    #[field(role = ciphertext, encoding = hex)]
    pub data: Vec<u8>,

    /// Optional bcrypt-pbkdf trailer, preserved verbatim.
    #[field(role = other, encoding = ascii)]
    pub extra: String,
}

pub fn sshng_modes(value: &Sshng) -> Vec<crate::Mode> {
    match value.cipher {
        0 => vec![crate::Mode::Hashcat(22911)],
        6 if value.extra.is_empty() => vec![crate::Mode::Hashcat(22921)],
        6 => vec![crate::Mode::Hashcat(36800)],
        1 | 3 => vec![crate::Mode::Hashcat(22931)],
        4 => vec![crate::Mode::Hashcat(22941)],
        5 => vec![crate::Mode::Hashcat(22951)],
        _ => Vec::new(),
    }
}

impl Parse for Sshng {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$sshng$", 0)?;
        let mut parts = rest.splitn(6, '$');
        let fields: Vec<(&str, usize)> = {
            let mut collected = Vec::new();
            let mut offset = 0;
            for part in &mut parts {
                collected.push((part, offset));
                offset += part.len() + 1;
            }
            collected
        };
        if fields.len() < 5 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                rest.len(),
                "SSH keys have at least five fields",
            ));
        }
        let extra = fields
            .get(5)
            .map(|field| field.0.to_owned())
            .unwrap_or_default();
        let cipher = fields[0].0.parse::<u8>().map_err(|_| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                fields[0].1,
                "invalid SSH cipher identifier",
            )
        })?;
        let iv_size = fields[1].0.parse::<usize>().map_err(|_| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                fields[1].1,
                "invalid SSH initialization vector size",
            )
        })?;
        let iv = parse::decode_hex(fields[2].0, fields[2].1)?;
        if iv.len() != iv_size {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                fields[2].1,
                "SSH initialization vector length does not match its header",
            ));
        }
        let data = parse::decode_hex(fields[4].0, fields[4].1)?;
        let expected = fields[3].0.parse::<usize>().map_err(|_| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                fields[3].1,
                "invalid SSH data length",
            )
        })?;
        if data.len() != expected {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                fields[4].1,
                "SSH data length does not match its header",
            ));
        }
        Ok(Self {
            cipher,
            iv,
            data,
            extra,
        })
    }
}

impl Render for Sshng {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        let data = crate::format::hex(&self.data);
        let mut value = format!(
            "$sshng${}${}${}${}${}",
            self.cipher,
            self.iv.len(),
            crate::format::hex(&self.iv),
            data.len() / 2,
            data
        );
        if !self.extra.is_empty() {
            value.push('$');
            value.push_str(&self.extra);
        }
        value
    }
}
