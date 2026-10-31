//! known_hosts hashes, rendered as `$known_hosts$|1|<salt>|<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// SSH known_hosts hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "known_hosts",
    slug = "known-hosts",
    hashcat = [],
    john = ["known_hosts"]
)]
pub struct KnownHosts {
    /// Base64 salt.
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// Base64 digest.
    #[field(role = digest, encoding = ascii)]
    pub digest: String,
}

impl Parse for KnownHosts {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$known_hosts$|1|", 0)?;
        let fields = parse::split_fields(rest, '|', 2)?;
        Ok(Self {
            salt: fields[0].0.to_owned(),
            digest: fields[1].0.to_owned(),
        })
    }
}

impl Render for KnownHosts {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$known_hosts$|1|{}|{}", self.salt, self.digest)
    }
}
