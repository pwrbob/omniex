//! Ethereum scrypt wallets, rendered as `$ethereum$s*<n>*<r>*<p>*<salt>*<ciphertext>*<mac>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Ethereum scrypt wallets.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Ethereum Wallet, SCRYPT",
    slug = "ethereum-scrypt",
    hashcat = [15700],
)]
pub struct EthereumScrypt {
    /// CPU/memory cost parameter
    #[field(role = iterations, encoding = decimal)]
    pub n: u32,

    /// Block size parameter
    #[field(role = other, encoding = decimal)]
    pub r: u32,

    /// Parallelization parameter
    #[field(role = other, encoding = decimal)]
    pub p: u32,

    /// Salt
    #[field(role = salt, encoding = hex)]
    pub salt: Vec<u8>,

    /// Ciphertext
    #[field(role = ciphertext, encoding = hex)]
    pub ciphertext: Vec<u8>,

    /// MAC
    #[field(role = digest, encoding = hex)]
    pub mac: Vec<u8>,
}

impl Parse for EthereumScrypt {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$ethereum$s*", 0)?;
        let fields = parse::split_fields(rest, '*', 6)?;
        let number = |field: (&str, usize), name: &str| {
            field.0.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    field.1,
                    format!("invalid scrypt {name}"),
                )
            })
        };
        Ok(Self {
            n: number(fields[0], "cost")?,
            r: number(fields[1], "block size")?,
            p: number(fields[2], "parallelization")?,
            salt: parse::decode_hex(fields[3].0, fields[3].1)?,
            ciphertext: parse::decode_hex(fields[4].0, fields[4].1)?,
            mac: parse::decode_hex(fields[5].0, fields[5].1)?,
        })
    }
}

impl Render for EthereumScrypt {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$ethereum$s*{}*{}*{}*{}*{}*{}",
            self.n,
            self.r,
            self.p,
            crate::format::hex(&self.salt),
            crate::format::hex(&self.ciphertext),
            crate::format::hex(&self.mac)
        )
    }
}
