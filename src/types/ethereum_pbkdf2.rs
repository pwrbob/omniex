//! Ethereum PBKDF2 wallets, rendered as `$ethereum$p*<iterations>*<salt>*<ciphertext>*<mac>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Ethereum PBKDF2-HMAC-SHA256 wallets.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Ethereum Wallet, PBKDF2-HMAC-SHA256",
    slug = "ethereum-pbkdf2",
    hashcat = [15600],
)]
pub struct EthereumPbkdf2 {
    /// Iteration count.
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// Hexadecimal salt.
    #[field(role = salt, encoding = hex)]
    pub salt: Vec<u8>,

    /// Hexadecimal ciphertext.
    #[field(role = ciphertext, encoding = hex)]
    pub ciphertext: Vec<u8>,

    /// Hexadecimal MAC.
    #[field(role = digest, encoding = hex)]
    pub mac: Vec<u8>,
}

impl Parse for EthereumPbkdf2 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$ethereum$p*", 0)?;
        let fields = parse::split_fields(rest, '*', 4)?;
        Ok(Self {
            iterations: fields[0].0.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    12,
                    "invalid Ethereum iteration count",
                )
            })?,
            salt: parse::decode_hex(fields[1].0, fields[1].1)?,
            ciphertext: parse::decode_hex(fields[2].0, fields[2].1)?,
            mac: parse::decode_hex(fields[3].0, fields[3].1)?,
        })
    }
}

impl Render for EthereumPbkdf2 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$ethereum$p*{}*{}*{}*{}",
            self.iterations,
            crate::format::hex(&self.salt),
            crate::format::hex(&self.ciphertext),
            crate::format::hex(&self.mac)
        )
    }
}
