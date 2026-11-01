//! Argon2 hashes, rendered as
//! `$argon2<variant>$v=<version>$m=<memory>,t=<iterations>,p=<parallelism>$<salt>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Argon2 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "Argon2", slug = "argon2", hashcat = [34000, 70000], john = ["Argon2"])]
pub struct Argon2 {
    /// Variant name, for example `argon2id`.
    #[field(role = other, encoding = ascii)]
    pub variant: String,

    /// Argon2 format version.
    #[field(role = other, encoding = decimal)]
    pub version: u32,

    /// Memory usage in KiB.
    #[field(role = other, encoding = decimal)]
    pub memory: u32,

    /// Iteration count.
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// Parallelism.
    #[field(role = other, encoding = decimal)]
    pub parallelism: u32,

    /// Base64 salt.
    #[field(role = salt, encoding = base64)]
    pub salt: Vec<u8>,

    /// Base64 digest.
    #[field(role = digest, encoding = base64)]
    pub digest: Vec<u8>,
}

impl Parse for Argon2 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$", 0)?;
        let (variant, rest, rest_offset) = parse::split_once(rest, '$', 1)?;
        if !matches!(variant, "argon2d" | "argon2i" | "argon2id") {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                1,
                "expected an Argon2 variant",
            ));
        }
        let fields = parse::split_fields(rest, '$', 4)?;
        let version = fields[0].0.strip_prefix("v=").ok_or_else(|| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                rest_offset,
                "expected an Argon2 version",
            )
        })?;
        let version = version.parse::<u32>().map_err(|_| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                rest_offset,
                "invalid Argon2 version",
            )
        })?;
        let params = fields[1].0.split(',').collect::<Vec<_>>();
        if params.len() != 3 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                rest_offset,
                "Argon2 parameters are memory, iterations, and parallelism",
            ));
        }
        fn parameter(value: &str, prefix: &str, offset: usize) -> Result<u32, ParseError> {
            value
                .strip_prefix(prefix)
                .and_then(|v| v.parse().ok())
                .ok_or_else(|| {
                    parse::error(
                        ParseErrorKind::InvalidCharacter,
                        offset,
                        format!("invalid Argon2 {prefix} parameter"),
                    )
                })
        }
        Ok(Self {
            variant: variant.to_owned(),
            version,
            memory: parameter(params[0], "m=", rest_offset)?,
            iterations: parameter(params[1], "t=", rest_offset)?,
            parallelism: parameter(params[2], "p=", rest_offset)?,
            salt: parse::decode_base64(fields[2].0, fields[2].1)?,
            digest: parse::decode_base64(fields[3].0, fields[3].1)?,
        })
    }
}

impl Render for Argon2 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "${}$v={}$m={},t={},p={}${}${}",
            self.variant,
            self.version,
            self.memory,
            self.iterations,
            self.parallelism,
            crate::format::base64_no_pad(&self.salt),
            crate::format::base64_no_pad(&self.digest)
        )
    }
}
