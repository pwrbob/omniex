//! Bisq wallet hashes, rendered as `$bisq$<version>*<n>*<r>*<p>*<salt>*<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Bisq wallet hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "Bisq .wallet (scrypt)", slug = "bisq", hashcat = [29800])]
pub struct Bisq {
    /// Format version
    #[field(role = other, encoding = decimal)]
    pub version: u8,

    /// scrypt cost parameter
    #[field(role = iterations, encoding = decimal)]
    pub n: u32,

    /// scrypt block size parameter
    #[field(role = other, encoding = decimal)]
    pub r: u8,

    /// scrypt parallelism
    #[field(role = other, encoding = decimal)]
    pub p: u8,

    /// 8-byte salt
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 8],

    /// 32-byte digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 32],
}

impl Parse for Bisq {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$bisq$", 0)?;
        let fields = parse::split_fields(rest, '*', 6)?;
        fn number(value: &str, offset: usize, name: &str) -> Result<u32, ParseError> {
            value.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    offset,
                    format!("invalid Bisq {name}"),
                )
            })
        }
        fn small(value: &str, offset: usize, name: &str) -> Result<u8, ParseError> {
            u8::try_from(number(value, offset, name)?).map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    offset,
                    format!("invalid Bisq {name}"),
                )
            })
        }
        Ok(Self {
            version: small(fields[0].0, fields[0].1, "version")?,
            n: number(fields[1].0, fields[1].1, "n")?,
            r: small(fields[2].0, fields[2].1, "r")?,
            p: small(fields[3].0, fields[3].1, "p")?,
            salt: parse::decode_hex_field::<8>(fields[4].0, fields[4].1, "salt")?,
            digest: parse::decode_hex_field::<32>(fields[5].0, fields[5].1, "digest")?,
        })
    }
}

impl Render for Bisq {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$bisq${}*{}*{}*{}*{}*{}",
            self.version,
            self.n,
            self.r,
            self.p,
            crate::format::hex(self.salt),
            crate::format::hex(self.digest)
        )
    }
}
