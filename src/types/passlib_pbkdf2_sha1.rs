//! Python passlib pbkdf2-sha1, rendered as `$pbkdf2$<iterations>$<salt>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Python passlib pbkdf2-sha1 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Python passlib pbkdf2-sha1",
    slug = "passlib-pbkdf2-sha1",
    hashcat = [40044],
)]
pub struct PasslibPbkdf2Sha1 {
    /// Iteration count
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// Passlib base64 salt text
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// Passlib base64 digest text
    #[field(role = digest, encoding = ascii)]
    pub digest: String,
}

impl Parse for PasslibPbkdf2Sha1 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        let rest = parse::strip_prefix(input, "$pbkdf2$", 0)?;
        let fields = parse::split_fields(rest, '$', 3)?;
        let (iterations, iterations_offset) = fields[0];
        let (salt, _) = fields[1];
        let (digest, _) = fields[2];

        let iterations = iterations.parse::<u32>().map_err(|_| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                "$pbkdf2$".len() + iterations_offset,
                "invalid passlib iteration count",
            )
        })?;
        Ok(Self {
            iterations,
            salt: salt.to_owned(),
            digest: digest.to_owned(),
        })
    }
}

impl Render for PasslibPbkdf2Sha1 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$pbkdf2${}${}${}", self.iterations, self.salt, self.digest)
    }
}
