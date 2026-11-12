//! TeamSpeak 3 channel hashes, rendered as `$teamspeak$3$<salt>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// TeamSpeak 3 channel hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Teamspeak 3 (channel hash)",
    slug = "teamspeak3",
    hashcat = [28300],
)]
pub struct Teamspeak3 {
    /// Base64 salt
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// Base64 digest
    #[field(role = digest, encoding = ascii)]
    pub digest: String,
}

impl Parse for Teamspeak3 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$teamspeak$3$", 0)?;
        let fields = parse::split_fields(rest, '$', 2)?;
        if fields[0].0.len() != 28 || fields[1].0.len() != 152 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                14,
                "TeamSpeak 3 salt and digest have fixed lengths",
            ));
        }
        Ok(Self {
            salt: fields[0].0.to_owned(),
            digest: fields[1].0.to_owned(),
        })
    }
}

impl Render for Teamspeak3 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$teamspeak$3${}${}", self.salt, self.digest)
    }
}
