//! John Kerberos 5 hashes, rendered as `$krb5$<fields>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Kerberos 5 hashes in the John serialization.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "Kerberos 5 legacy", slug = "krb5-legacy", hashcat = [], john = ["krb5"])]
pub struct Krb5John {
    /// Version-specific fields, preserved verbatim.
    #[field(role = other, encoding = ascii)]
    pub fields: String,
}

impl Parse for Krb5John {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$krb5$", 0)?;
        if rest.is_empty() {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                6,
                "missing Kerberos 5 fields",
            ));
        }
        Ok(Self {
            fields: rest.to_owned(),
        })
    }
}

impl Render for Krb5John {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$krb5${}", self.fields)
    }
}
