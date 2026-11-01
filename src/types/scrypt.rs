//! scrypt, rendered as `SCRYPT:<n>:<r>:<p>:<salt>:<digest>`.

use crate::parse;
use crate::{
    HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions, Tool,
};

/// scrypt password hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "scrypt",
    slug = "scrypt",
    hashcat = [8900],
    john = ["scrypt"],
)]
pub struct Scrypt {
    /// CPU/memory cost parameter.
    #[field(role = iterations, encoding = decimal)]
    pub n: u32,

    /// Block size parameter.
    #[field(role = other, encoding = decimal)]
    pub r: u32,

    /// Parallelization parameter.
    #[field(role = other, encoding = decimal)]
    pub p: u32,

    /// Base64-encoded salt.
    #[field(role = salt, encoding = base64)]
    pub salt: Vec<u8>,

    /// Base64-encoded digest.
    #[field(role = digest, encoding = base64)]
    pub digest: Vec<u8>,
}

impl Parse for Scrypt {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        if let Some(rest) = input.strip_prefix("$ScryptKDF.pm$") {
            let fields = parse::split_fields(rest, '*', 5)?;
            let number = |field: (&str, usize), name: &str| {
                field.0.parse::<u32>().map_err(|_| {
                    parse::error(
                        ParseErrorKind::InvalidCharacter,
                        field.1,
                        format!("invalid scrypt {name}"),
                    )
                })
            };
            return Ok(Self {
                n: number(fields[0], "cost")?,
                r: number(fields[1], "block size")?,
                p: number(fields[2], "parallelization")?,
                salt: parse::decode_base64(fields[3].0, fields[3].1)?,
                digest: parse::decode_base64(fields[4].0, fields[4].1)?,
            });
        }
        let rest = parse::strip_prefix(input, "SCRYPT:", 0)?;
        let fields = parse::split_fields(rest, ':', 5)?;
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
            salt: parse::decode_base64(fields[3].0, fields[3].1)?,
            digest: parse::decode_base64(fields[4].0, fields[4].1)?,
        })
    }
}

impl Render for Scrypt {
    fn render_value(&self, opts: &RenderOptions) -> String {
        if opts.tool == Tool::John {
            return format!(
                "$ScryptKDF.pm${}*{}*{}*{}*{}",
                self.n,
                self.r,
                self.p,
                crate::format::base64(&self.salt),
                crate::format::base64(&self.digest)
            );
        }
        format!(
            "SCRYPT:{}:{}:{}:{}:{}",
            self.n,
            self.r,
            self.p,
            crate::format::base64(&self.salt),
            crate::format::base64(&self.digest)
        )
    }
}
