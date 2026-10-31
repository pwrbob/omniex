//! SolarWinds Orion, rendered as `$solarwinds$<version>$<salt>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// SolarWinds Orion hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "SolarWinds Orion",
    slug = "solarwinds",
    hashcat = [21500, 21501], john = ["solarwinds"],
    modes_fn = solarwinds_modes,
)]
pub struct Solarwinds {
    /// Format version, which selects the mode.
    #[field(role = other, encoding = decimal)]
    pub version: u8,

    /// Base64 salt or username field.
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// Base64 digest.
    #[field(role = digest, encoding = ascii)]
    pub digest: String,
}

pub fn solarwinds_modes(value: &Solarwinds) -> Vec<crate::Mode> {
    match value.version {
        0 => vec![crate::Mode::Hashcat(21500)],
        1 => vec![crate::Mode::Hashcat(21501)],
        _ => Vec::new(),
    }
}

impl Parse for Solarwinds {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$solarwinds$", 0)?;
        let fields = parse::split_fields(rest, '$', 3)?;
        Ok(Self {
            version: fields[0].0.parse::<u8>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    12,
                    "invalid SolarWinds version",
                )
            })?,
            salt: fields[1].0.to_owned(),
            digest: fields[2].0.to_owned(),
        })
    }
}

impl Render for Solarwinds {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$solarwinds${}${}${}", self.version, self.salt, self.digest)
    }
}
