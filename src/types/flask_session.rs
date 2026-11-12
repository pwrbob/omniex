//! Flask session cookies, rendered as `<payload>.<timestamp>.<signature>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// Flask session cookie hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Flask Session Cookie",
    slug = "flask-session",
    hashcat = [40056]
)]
pub struct FlaskSession {
    /// Base64url payload
    #[field(role = other, encoding = ascii)]
    pub payload: String,

    /// Base64url timestamp
    #[field(role = salt, encoding = ascii)]
    pub timestamp: String,

    /// Base64url signature
    #[field(role = digest, encoding = ascii)]
    pub signature: String,
}

impl Parse for FlaskSession {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let fields = parse::split_fields(input, '.', 3)?;
        Ok(Self {
            payload: fields[0].0.to_owned(),
            timestamp: fields[1].0.to_owned(),
            signature: fields[2].0.to_owned(),
        })
    }
}

impl Render for FlaskSession {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("{}.{}.{}", self.payload, self.timestamp, self.signature)
    }
}
