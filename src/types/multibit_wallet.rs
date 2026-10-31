//! MultiBit Classic .wallet, rendered as `$multibit$3*<n>*<r>*<p>*<salt>*<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// MultiBit Classic .wallet hashes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "MultiBit Classic .wallet (scrypt)",
    slug = "multibit-wallet",
    hashcat = [27700],
)]
pub struct MultibitWallet {
    /// CPU/memory cost parameter.
    #[field(role = iterations, encoding = decimal)]
    pub n: u32,

    /// Block size parameter.
    #[field(role = other, encoding = decimal)]
    pub r: u32,

    /// Parallelization parameter.
    #[field(role = other, encoding = decimal)]
    pub p: u32,

    /// The 8-byte salt.
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 8],

    /// The 32-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 32],
}

impl Parse for MultibitWallet {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$multibit$3*", 0)?;
        let fields = parse::split_fields(rest, '*', 5)?;
        let number = |field: (&str, usize), name: &str| {
            field.0.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    field.1,
                    format!("invalid MultiBit {name}"),
                )
            })
        };
        Ok(Self {
            n: number(fields[0], "cost")?,
            r: number(fields[1], "block size")?,
            p: number(fields[2], "parallelization")?,
            salt: parse::decode_hex_field::<8>(fields[3].0, fields[3].1, "salt")?,
            digest: parse::decode_hex_field::<32>(fields[4].0, fields[4].1, "digest")?,
        })
    }
}

impl Render for MultibitWallet {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$multibit$3*{}*{}*{}*{}*{}",
            self.n,
            self.r,
            self.p,
            crate::format::hex(self.salt),
            crate::format::hex(self.digest)
        )
    }
}
