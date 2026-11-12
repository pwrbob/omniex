//! Drupal 7, rendered as `$S$<cost><salt><digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Drupal 7 password hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Drupal7",
    slug = "drupal7",
    hashcat = [40020],
    john = ["Drupal7"],
)]
pub struct Drupal7 {
    /// Drupal iteration character
    #[field(role = iterations, encoding = ascii)]
    pub cost: String,

    /// 8-character salt
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// 43-character digest
    #[field(role = digest, encoding = ascii)]
    pub digest: String,
}

impl Parse for Drupal7 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        let rest = parse::strip_prefix(input, "$S$", 0)?;
        if rest.len() != 52 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                input.len(),
                "Drupal7 values are 55 characters",
            ));
        }

        Ok(Self {
            cost: rest[..1].to_owned(),
            salt: rest[1..9].to_owned(),
            digest: rest[9..].to_owned(),
        })
    }
}

impl Render for Drupal7 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$S${}{}{}", self.cost, self.salt, self.digest)
    }
}
