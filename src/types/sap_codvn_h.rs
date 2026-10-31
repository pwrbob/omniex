//! SAP CODVN H hashes, rendered as
//! `{x-<scheme>, <iterations>}<base64 payload>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// SAP CODVN H (PWDSALTEDHASH) hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "SAP CODVN H",
    slug = "sap-codvn-h",
    hashcat = [40023, 40078, 40081, 40082],
    modes_fn = sap_codvn_h_modes,
)]
pub struct SapCodvnH {
    /// Scheme name, which selects the mode.
    #[field(role = other, encoding = ascii)]
    pub scheme: String,

    /// Iteration count.
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// Base64 salt and digest payload.
    #[field(role = salt, encoding = base64)]
    pub payload: Vec<u8>,
}

pub fn sap_codvn_h_modes(value: &SapCodvnH) -> Vec<crate::Mode> {
    match value.scheme.as_str() {
        "issha" => vec![crate::Mode::Hashcat(40023)],
        "isSHA256" => vec![crate::Mode::Hashcat(40081)],
        "isSHA384" => vec![crate::Mode::Hashcat(40082)],
        "isSHA512" => vec![crate::Mode::Hashcat(40078)],
        _ => Vec::new(),
    }
}

impl Parse for SapCodvnH {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "{x-", 0)?;
        let (scheme, rest, rest_offset) = parse::split_once(rest, ',', 3)?;
        let rest = rest.strip_prefix(' ').ok_or_else(|| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                rest_offset,
                "expected a space after the SAP scheme",
            )
        })?;
        let iterations_text = rest.split_once('}').ok_or_else(|| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                rest_offset,
                "expected a closing brace",
            )
        })?;
        let iterations = iterations_text.0.parse::<u32>().map_err(|_| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                rest_offset,
                "invalid SAP iteration count",
            )
        })?;
        Ok(Self {
            scheme: scheme.to_owned(),
            iterations,
            payload: parse::decode_base64(
                iterations_text.1,
                rest_offset + iterations_text.0.len() + 1,
            )?,
        })
    }
}

impl Render for SapCodvnH {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "{{x-{}, {}}}{}",
            self.scheme,
            self.iterations,
            crate::format::base64(&self.payload)
        )
    }
}
