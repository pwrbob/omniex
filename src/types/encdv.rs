//! ENCsecurity DataVault hashes, rendered as
//! `$<scheme>$<version>$<param>$<salt>$<check>[$<data>]`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// ENCsecurity DataVault hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "ENCsecurity DataVault",
    slug = "encdv",
    hashcat = [29910, 29920, 29930, 29940],
    modes_fn = encdv_modes,
)]
pub struct Encdv {
    /// Scheme name, `encdv-pbkdf2` or `encdv`.
    #[field(role = other, encoding = ascii)]
    pub scheme: String,

    /// Format version.
    #[field(role = other, encoding = decimal)]
    pub version: u8,

    /// Scheme-specific parameter.
    #[field(role = other, encoding = decimal)]
    pub parameter: u8,

    /// Eight-byte salt.
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 8],

    /// Eight-byte check value.
    #[field(role = other, encoding = hex)]
    pub check: [u8; 8],

    /// Scheme-specific remainder, empty when absent.
    #[field(role = other, encoding = ascii)]
    pub extra: String,
}

pub fn encdv_modes(value: &Encdv) -> Vec<crate::Mode> {
    match value.scheme.as_str() {
        "encdv-pbkdf2" if value.extra.matches('$').count() >= 3 => {
            vec![crate::Mode::Hashcat(29920)]
        }
        "encdv-pbkdf2" => vec![crate::Mode::Hashcat(29910)],
        "encdv" if value.extra.is_empty() => vec![crate::Mode::Hashcat(29930)],
        "encdv" => vec![crate::Mode::Hashcat(29940)],
        _ => Vec::new(),
    }
}

impl Parse for Encdv {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$", 0)?;
        let (scheme, rest, rest_offset) = parse::split_once(rest, '$', 1)?;
        if !matches!(scheme, "encdv" | "encdv-pbkdf2") {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                1,
                "expected an ENCsecurity scheme",
            ));
        }
        let mut fields = rest.splitn(5, '$');
        let version = fields.next().unwrap_or_default();
        let parameter = fields.next().unwrap_or_default();
        let salt = fields.next().unwrap_or_default();
        let check = fields.next().unwrap_or_default();
        let extra = fields.next().unwrap_or_default().to_owned();
        Ok(Self {
            scheme: scheme.to_owned(),
            version: version.parse::<u8>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    rest_offset,
                    "invalid version",
                )
            })?,
            parameter: parameter.parse::<u8>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    rest_offset,
                    "invalid parameter",
                )
            })?,
            salt: parse::decode_hex_field::<8>(salt, rest_offset, "salt")?,
            check: parse::decode_hex_field::<8>(check, rest_offset, "check")?,
            extra,
        })
    }
}

impl Render for Encdv {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        let mut value = format!(
            "${}${}${}${}${}",
            self.scheme,
            self.version,
            self.parameter,
            crate::format::hex(self.salt),
            crate::format::hex(self.check)
        );
        if !self.extra.is_empty() {
            value.push('$');
            value.push_str(&self.extra);
        }
        value
    }
}
