//! bcrypt, rendered as `$2a$<cost>$<salt><digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// bcrypt password hash.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "bcrypt",
    slug = "bcrypt",
    hashcat = [3200],
    john = ["bcrypt"],
)]
pub struct Bcrypt {
    /// Version prefix, for example `$2a$`.
    #[field(role = other, encoding = ascii)]
    pub prefix: String,

    /// Cost parameter.
    #[field(role = iterations, encoding = decimal)]
    pub cost: u32,

    /// Twenty-two base64 salt characters.
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// Thirty-one base64 digest characters.
    #[field(role = digest, encoding = ascii)]
    pub digest: String,
}

impl Parse for Bcrypt {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        if input.len() != 60 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                0,
                "bcrypt hash must be 60 characters",
            ));
        }

        let prefix = &input[..4];
        if !matches!(prefix, "$2a$" | "$2b$" | "$2y$") {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                0,
                "expected `$2a$`, `$2b$`, or `$2y$` prefix",
            ));
        }

        let cost = input[4..6].parse::<u32>().map_err(|_| {
            parse::error(ParseErrorKind::InvalidCharacter, 4, "invalid bcrypt cost")
        })?;
        let salt = &input[7..29];
        let digest = &input[29..60];

        Ok(Self {
            prefix: prefix.to_owned(),
            cost,
            salt: salt.to_owned(),
            digest: digest.to_owned(),
        })
    }
}

impl Render for Bcrypt {
    fn render(&self, _opts: &RenderOptions) -> String {
        format!(
            "{}{:02}${}{}",
            self.prefix, self.cost, self.salt, self.digest
        )
    }
}
