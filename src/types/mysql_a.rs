//! MySQL `$A$` hashes, rendered as `$mysql$A$<rounds>*<salt>*<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// MySQL `$A$` (sha256crypt) hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "MySQL $A$ (sha256crypt)",
    slug = "mysql-a",
    hashcat = [7401],
)]
pub struct MysqlA {
    /// Rounds (keeps zeroes)
    #[field(role = iterations, encoding = ascii)]
    pub rounds: String,

    /// Hexadecimal salt
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// Digest
    #[field(role = digest, encoding = ascii)]
    pub digest: String,
}

impl Parse for MysqlA {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$mysql$A$", 0)?;
        let fields = parse::split_fields(rest, '*', 3)?;
        if !(3..=4).contains(&fields[0].0.len()) {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                9,
                "MySQL rounds must be three or four characters",
            ));
        }
        Ok(Self {
            rounds: fields[0].0.to_owned(),
            salt: fields[1].0.to_owned(),
            digest: fields[2].0.to_owned(),
        })
    }
}

impl Render for MysqlA {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$mysql$A${}*{}*{}", self.rounds, self.salt, self.digest)
    }
}
