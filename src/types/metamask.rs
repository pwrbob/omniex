//! MetaMask wallets, rendered as `$metamask$<salt>$<iv>$<ciphertext>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// MetaMask wallet hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "MetaMask Wallet",
    slug = "metamask",
    hashcat = [26600, 26610],
    modes_fn = metamask_modes,
)]
pub struct Metamask {
    /// Salt
    #[field(role = salt, encoding = base64)]
    pub salt: Vec<u8>,

    /// 16-byte IV
    #[field(role = iv, encoding = base64)]
    pub iv: [u8; 16],

    /// Ciphertext
    #[field(role = ciphertext, encoding = base64)]
    pub ciphertext: Vec<u8>,
}

impl Parse for Metamask {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = input
            .strip_prefix("$metamask-short$")
            .or_else(|| input.strip_prefix("$metamask$"))
            .ok_or_else(|| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    0,
                    "expected `$metamask$` or `$metamask-short$`",
                )
            })?;
        let fields = parse::split_fields(rest, '$', 3)?;
        let salt = parse::decode_base64(fields[0].0, fields[0].1)?;
        let iv = parse::decode_base64(fields[1].0, fields[1].1)?;
        let ciphertext = parse::decode_base64(fields[2].0, fields[2].1)?;
        let iv = iv.as_slice().try_into().map_err(|_| {
            parse::error(
                ParseErrorKind::InvalidLength,
                fields[1].1,
                "MetaMask IV must be 16 bytes",
            )
        })?;
        Ok(Self {
            salt,
            iv,
            ciphertext,
        })
    }
}

pub fn metamask_modes(value: &Metamask) -> Vec<crate::Mode> {
    if value.ciphertext.len() == 64 {
        vec![crate::Mode::Hashcat(26610)]
    } else {
        vec![crate::Mode::Hashcat(26600)]
    }
}

impl Render for Metamask {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "{}{}${}${}",
            if self.ciphertext.len() == 64 {
                "$metamask-short$"
            } else {
                "$metamask$"
            },
            crate::format::base64(&self.salt),
            crate::format::base64(self.iv),
            crate::format::base64(&self.ciphertext)
        )
    }
}
