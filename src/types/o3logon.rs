//! Oracle O3LOGON hashes, rendered as `$o3logon$<user>$<digest1>$<digest2>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// Oracle O3LOGON hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "Oracle O3LOGON", slug = "o3logon", hashcat = [], john = ["o3logon"])]
pub struct O3logon {
    /// User name
    #[field(role = username, encoding = ascii)]
    pub username: String,

    /// First sixteen-byte digest
    #[field(role = digest, encoding = ascii)]
    pub digest1: String,

    /// Second sixteen-byte digest
    #[field(role = other, encoding = ascii)]
    pub digest2: String,
}

impl Parse for O3logon {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$o3logon$", 0)?;
        let fields = parse::split_fields(rest, '$', 3)?;
        Ok(Self {
            username: fields[0].0.to_owned(),
            digest1: fields[1].0.to_owned(),
            digest2: fields[2].0.to_owned(),
        })
    }
}

impl Render for O3logon {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$o3logon${}${}${}",
            self.username, self.digest1, self.digest2
        )
    }
}
