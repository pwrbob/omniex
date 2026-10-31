//! krb5pa-md5 hashes, rendered as the serialized hash payload.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// krb5pa-md5 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "krb5pa-md5", slug = "krb5pa-md5", hashcat = [], john = ["krb5pa-md5"])]
pub struct Krb5paMd5John {
    /// Serialized hash payload.
    #[field(role = other, encoding = ascii)]
    pub data: String,
}

impl Parse for Krb5paMd5John {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$krb5pa$", 0)?;
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

impl Render for Krb5paMd5John {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$krb5pa${}", self.data)
    }
}
