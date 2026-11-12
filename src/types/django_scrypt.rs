//! django-scrypt hashes, rendered as the serialized hash payload.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// django-scrypt hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "django-scrypt", slug = "django-scrypt", hashcat = [], john = ["django-scrypt"])]
pub struct DjangoScryptJohn {
    /// Serialized hash payload
    #[field(role = other, encoding = ascii)]
    pub data: String,
}

impl Parse for DjangoScryptJohn {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "scrypt$", 0)?;
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

impl Render for DjangoScryptJohn {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("scrypt${}", self.data)
    }
}
