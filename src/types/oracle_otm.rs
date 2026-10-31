//! Oracle Transportation Management hashes, rendered as
//! `otm_sha256:<iterations>:<salt>:<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Oracle Transportation Management SHA256 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Oracle Transportation Management",
    slug = "oracle-otm",
    hashcat = [40045]
)]
pub struct OracleOtm {
    /// Iteration count.
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// Salt value.
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// Base64 digest.
    #[field(role = digest, encoding = base64)]
    pub digest: Vec<u8>,
}

impl Parse for OracleOtm {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "otm_sha256:", 0)?;
        let fields = parse::split_fields(rest, ':', 3)?;
        let iterations = fields[0].0.parse::<u32>().map_err(|_| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                fields[0].1,
                "invalid OTM iteration count",
            )
        })?;
        Ok(Self {
            iterations,
            salt: fields[1].0.to_owned(),
            digest: parse::decode_base64(fields[2].0, fields[2].1)?,
        })
    }
}

impl Render for OracleOtm {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "otm_sha256:{}:{}:{}",
            self.iterations,
            self.salt,
            crate::format::base64(&self.digest)
        )
    }
}
