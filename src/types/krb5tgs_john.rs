//! krb5tgs hashes, rendered as the serialized hash payload.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// krb5tgs hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "Kerberos 5 TGS-REP payload", slug = "krb5tgs-payload", hashcat = [], john = ["krb5tgs"])]
pub struct Krb5tgsJohn {
    /// Serialized hash payload
    #[field(role = other, encoding = ascii)]
    pub data: String,
}

impl Parse for Krb5tgsJohn {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$krb5tgs$", 0)?;
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

impl Render for Krb5tgsJohn {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$krb5tgs${}", self.data)
    }
}
