//! KDE KWallet hashes, rendered as `$kwallet$<version>$<data>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// KDE KWallet hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "KDE KWallet",
    slug = "kwallet",
    hashcat = [36400, 36410], john = ["kwallet"],
    modes_fn = kwallet_modes,
)]
pub struct Kwallet {
    /// Hash version
    #[field(role = other, encoding = decimal)]
    pub version: u32,

    /// Version-specific fields
    #[field(role = other, encoding = ascii)]
    pub data: String,
}

pub fn kwallet_modes(value: &Kwallet) -> Vec<crate::Mode> {
    if value.data.contains("$") {
        vec![crate::Mode::Hashcat(36400)]
    } else {
        vec![crate::Mode::Hashcat(36410)]
    }
}

impl Parse for Kwallet {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$kwallet$", 0)?;
        let (version, data, data_offset) = parse::split_once(rest, '$', 9)?;
        if data.is_empty() {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                data_offset,
                "missing KWallet data",
            ));
        }
        Ok(Self {
            version: version.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    9,
                    "invalid KWallet version",
                )
            })?,
            data: data.to_owned(),
        })
    }
}

impl Render for Kwallet {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$kwallet${}${}", self.version, self.data)
    }
}
