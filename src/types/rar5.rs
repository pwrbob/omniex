//! RAR5 header encryption hashes, rendered as
//! `$rar5$16$<salt>$<log2 iterations>$<iv>$8$<password check>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// RAR5 header encryption hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "RAR5", slug = "rar5", hashcat = [13000], john = ["RAR5"])]
pub struct Rar5 {
    /// 16-byte salt
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 16],

    /// Iteration exponent (base 2)
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u8,

    /// 16-byte IV
    #[field(role = other, encoding = hex)]
    pub iv: [u8; 16],

    /// 8-byte password check value
    #[field(role = digest, encoding = hex)]
    pub password_check: [u8; 8],
}

impl Parse for Rar5 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$rar5$16$", 0)?;
        let fields = parse::split_fields(rest, '$', 5)?;
        let iterations = fields[1].0.parse::<u8>().map_err(|_| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                fields[1].1,
                "invalid RAR5 iteration count",
            )
        })?;
        if iterations > 31 {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                fields[1].1,
                "RAR5 iteration exponents are at most 31",
            ));
        }
        Ok(Self {
            salt: parse::decode_hex_field::<16>(fields[0].0, 9, "salt")?,
            iterations,
            iv: parse::decode_hex_field::<16>(fields[2].0, fields[2].1, "iv")?,
            password_check: parse::decode_hex_field::<8>(
                fields[4].0,
                fields[4].1,
                "password check",
            )?,
        })
    }
}

impl Render for Rar5 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$rar5$16${}${}${}$8${}",
            crate::format::hex(self.salt),
            self.iterations,
            crate::format::hex(self.iv),
            crate::format::hex(self.password_check)
        )
    }
}
