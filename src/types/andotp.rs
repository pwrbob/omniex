//! andOTP hashes, rendered as `$andotp$<version>*<salt>*<iterations>*<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// andOTP hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "andOTP", slug = "andotp", hashcat = [], john = ["andOTP"])]
pub struct Andotp {
    /// Format version.
    #[field(role = other, encoding = decimal)]
    pub version: u8,

    /// Salt.
    #[field(role = salt, encoding = hex)]
    pub salt: String,

    /// Iteration count.
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// Sixteen-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 16],
}

impl Parse for Andotp {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$andotp$", 0)?;
        let fields = parse::split_fields(rest, '*', 4)?;
        Ok(Self {
            version: fields[0].0.parse::<u8>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    8,
                    "invalid andOTP version",
                )
            })?,
            salt: fields[1].0.to_owned(),
            iterations: u32::from_str_radix(fields[2].0, 16).map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    fields[2].1,
                    "invalid andOTP iteration count",
                )
            })?,
            digest: parse::decode_hex_field::<16>(fields[3].0, fields[3].1, "digest")?,
        })
    }
}

impl Render for Andotp {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$andotp${}*{}*{:x}*{}",
            self.version,
            self.salt,
            self.iterations,
            crate::format::hex(self.digest)
        )
    }
}
