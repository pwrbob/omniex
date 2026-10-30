//! MetaMask short hash, rendered as `$metamask-short$<salt>$<iv>$<ciphertext>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// MetaMask short wallet hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "MetaMask Wallet (short hash, plaintext check)",
    slug = "metamask-short",
    hashcat = [26610],
)]
pub struct MetamaskShort {
    /// Base64 salt.
    #[field(role = salt, encoding = base64)]
    pub salt: Vec<u8>,

    /// The 16-byte IV.
    #[field(role = iv, encoding = base64)]
    pub iv: [u8; 16],

    /// The 64-byte ciphertext.
    #[field(role = ciphertext, encoding = base64)]
    pub ciphertext: [u8; 64],
}

impl Parse for MetamaskShort {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$metamask-short$", 0)?;
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
        let ciphertext = ciphertext.as_slice().try_into().map_err(|_| {
            parse::error(
                ParseErrorKind::InvalidLength,
                fields[2].1,
                "MetaMask ciphertext must be 64 bytes",
            )
        })?;
        Ok(Self {
            salt,
            iv,
            ciphertext,
        })
    }
}

impl Render for MetamaskShort {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$metamask-short${}${}${}",
            crate::format::base64(&self.salt),
            crate::format::base64(self.iv),
            crate::format::base64(self.ciphertext)
        )
    }
}
