//! krb5pa-md5 hashes, rendered as the serialized hash payload.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// krb5pa-md5 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "krb5pa-md5", slug = "krb5pa-md5", hashcat = [], john = ["krb5pa-md5"])]
pub struct Krb5paMd5John {
    /// Serialized hash payload
    #[field(role = other, encoding = ascii)]
    pub data: String,
}

impl Parse for Krb5paMd5John {
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
            .strip_prefix("krb5pa$23$")
            .or_else(|| rest.strip_prefix("mskrb5$"));
        if payload.is_none_or(str::is_empty) {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                0,
                "expected `$krb5pa$23$` or `$mskrb5$`",
            ));
        }
        Ok(Self {
            data: rest.to_owned(),
        })
    }
}

impl Render for Krb5paMd5John {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("${}", self.data)
    }
}
