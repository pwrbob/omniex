//! WordPress bcrypt(hmac-sha384) hashes, rendered as
//! `$wp$<version>$<cost>$<salt><digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// WordPress bcrypt(hmac-sha384) hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "WordPress bcrypt(hmac-sha384)",
    slug = "wordpress-bcrypt",
    hashcat = [35500]
)]
pub struct WordpressBcrypt {
    /// bcrypt version marker.
    #[field(role = other, encoding = ascii)]
    pub version: String,

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

impl Parse for WordpressBcrypt {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$wp$", 0)?;
        let fields = parse::split_fields(rest, '$', 3)?;
        let cost = fields[1].0.parse::<u32>().map_err(|_| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                fields[1].1,
                "invalid WordPress bcrypt cost",
            )
        })?;
        if fields[2].0.len() != 53 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                fields[2].1,
                "WordPress bcrypt salt and digest are 53 characters",
            ));
        }
        Ok(Self {
            version: fields[0].0.to_owned(),
            cost,
            salt: fields[2].0[..22].to_owned(),
            digest: fields[2].0[22..].to_owned(),
        })
    }
}

impl Render for WordpressBcrypt {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$wp${}${}${}{}",
            self.version, self.cost, self.salt, self.digest
        )
    }
}
