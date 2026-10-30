//! DNSSEC NSEC3, rendered as `<digest>:<domain>:<salt>:<iterations>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// DNSSEC NSEC3 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "DNSSEC (NSEC3)",
    slug = "nsec3",
    hashcat = [8300],
)]
pub struct Nsec3 {
    /// Base32 digest.
    #[field(role = digest, encoding = ascii)]
    pub digest: String,

    /// Domain name.
    #[field(role = other, encoding = ascii)]
    pub domain: String,

    /// ASCII salt.
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// Iteration count.
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,
}

impl Parse for Nsec3 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let fields = parse::split_fields(input, ':', 4)?;
        Ok(Self {
            digest: fields[0].0.to_owned(),
            domain: fields[1].0.to_owned(),
            salt: fields[2].0.to_owned(),
            iterations: fields[3].0.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    fields[3].1,
                    "invalid NSEC3 iteration count",
                )
            })?,
        })
    }
}

impl Render for Nsec3 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "{}:{}:{}:{}",
            self.digest, self.domain, self.salt, self.iterations
        )
    }
}
