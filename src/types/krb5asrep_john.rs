//! krb5asrep hashes, rendered as the serialized hash payload.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// krb5asrep hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "Kerberos 5 AS-REP payload", slug = "krb5asrep-payload", hashcat = [], john = ["krb5asrep"])]
pub struct Krb5asrepJohn {
    /// Serialized hash payload
    #[field(role = other, encoding = ascii)]
    pub data: String,
}

impl Parse for Krb5asrepJohn {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$krb5asrep$", 0)?;
        if rest.is_empty() {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                0,
                "missing hash payload",
            ));
        }
        Ok(Self {
            data: rest.to_owned(),
        })
    }
}

impl Render for Krb5asrepJohn {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$krb5asrep${}", self.data)
    }
}
