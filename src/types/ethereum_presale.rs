//! Ethereum pre-sale wallet, rendered as `$ethereum$w*<seed>*<address>*<mac>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// Ethereum pre-sale wallets.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Ethereum Pre-Sale Wallet, PBKDF2-HMAC-SHA256",
    slug = "ethereum-presale",
    hashcat = [16300],
    john = ["ethereum-presale-opencl"],
)]
pub struct EthereumPresale {
    /// Hexadecimal encrypted seed.
    #[field(role = ciphertext, encoding = hex)]
    pub encrypted_seed: Vec<u8>,

    /// The 20-byte Ethereum address.
    #[field(role = other, encoding = hex)]
    pub address: [u8; 20],

    /// The 16-byte MAC.
    #[field(role = digest, encoding = hex)]
    pub mac: [u8; 16],
}

impl Parse for EthereumPresale {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$ethereum$w*", 0)?;
        let fields = parse::split_fields(rest, '*', 3)?;
        Ok(Self {
            encrypted_seed: parse::decode_hex(fields[0].0, fields[0].1)?,
            address: parse::decode_hex_field::<20>(fields[1].0, fields[1].1, "address")?,
            mac: parse::decode_hex_field::<16>(fields[2].0, fields[2].1, "mac")?,
        })
    }
}

impl Render for EthereumPresale {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$ethereum$w*{}*{}*{}",
            crate::format::hex(&self.encrypted_seed),
            crate::format::hex(self.address),
            crate::format::hex(self.mac)
        )
    }
}
