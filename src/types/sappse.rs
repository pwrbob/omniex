//! SAP PSE hashes, rendered as `$pse$<version>$<fields>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// SAP PSE hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "SAP PSE", slug = "sappse", hashcat = [], john = ["sappse"])]
pub struct Sappse {
    /// Format version.
    #[field(role = other, encoding = decimal)]
    pub version: u8,

    /// Remaining fields, preserved verbatim.
    #[field(role = other, encoding = ascii)]
    pub fields: String,
}

impl Parse for Sappse {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$pse$", 0)?;
        let (version, fields, _) = parse::split_once(rest, '$', 5)?;
        if fields.is_empty() {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                5,
                "missing SAP PSE fields",
            ));
        }
        Ok(Self {
            version: version.parse::<u8>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    5,
                    "invalid SAP PSE version",
                )
            })?,
            fields: fields.to_owned(),
        })
    }
}

impl Render for Sappse {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$pse${}${}", self.version, self.fields)
    }
}
