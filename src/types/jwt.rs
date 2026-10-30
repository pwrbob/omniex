//! JWT, rendered as `<header>.<payload>.<signature>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// JSON Web Token signatures.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "JWT (JSON Web Token)",
    slug = "jwt",
    hashcat = [16500],
)]
pub struct Jwt {
    /// Base64url header segment.
    #[field(role = other, encoding = ascii)]
    pub header: String,

    /// Base64url payload segment.
    #[field(role = other, encoding = ascii)]
    pub payload: String,

    /// Base64url signature segment.
    #[field(role = digest, encoding = ascii)]
    pub signature: String,
}

impl Parse for Jwt {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let fields = parse::split_fields(input, '.', 3)?;
        if fields[2].0.len() < 43 || fields[2].0.len() > 86 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                fields[2].1,
                "JWT signature must be 43 to 86 characters",
            ));
        }
        Ok(Self {
            header: fields[0].0.to_owned(),
            payload: fields[1].0.to_owned(),
            signature: fields[2].0.to_owned(),
        })
    }
}

impl Render for Jwt {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("{}.{}.{}", self.header, self.payload, self.signature)
    }
}
