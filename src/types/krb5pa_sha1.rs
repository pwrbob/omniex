//! krb5pa-sha1 hashes, rendered as the serialized hash payload.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// krb5pa-sha1 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "krb5pa-sha1", slug = "krb5pa-sha1", hashcat = [], john = ["krb5pa-sha1"])]
pub struct Krb5paSha1John {
    /// Serialized hash payload
    #[field(role = other, encoding = ascii)]
    pub data: String,
}

impl Parse for Krb5paSha1John {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = input.strip_prefix('$').ok_or_else(|| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                0,
                "expected a tagged Kerberos pre-authentication hash",
            )
        })?;
        let payload = rest
            .strip_prefix("krb5pa$17$")
            .or_else(|| rest.strip_prefix("krb5pa$18$"));
        if payload.is_none_or(str::is_empty) {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                0,
                "expected `$krb5pa$17$` or `$krb5pa$18$`",
            ));
        }
        Ok(Self {
            data: rest.to_owned(),
        })
    }
}

impl Render for Krb5paSha1John {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("${}", self.data)
    }
}
