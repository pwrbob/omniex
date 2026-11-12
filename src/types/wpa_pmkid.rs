//! WPA PMKID/EAPOL hashes in the hashcat 22000 format.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// A WPA PMKID or EAPOL frame in the compact `WPA*` format.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "WPA-PMKID/EAPOL",
    slug = "wpa-pmkid",
    hashcat = [22000, 22001],
)]
pub struct WpaPmkid {
    /// Frame type (`01` = PMKID)
    #[field(role = other, encoding = ascii)]
    pub kind: String,

    /// 16-byte PMKID
    #[field(role = digest, encoding = hex)]
    pub pmkid: [u8; 16],

    /// Access point MAC address
    #[field(role = other, encoding = hex)]
    pub access_point: [u8; 6],

    /// Station MAC address
    #[field(role = other, encoding = hex)]
    pub station: [u8; 6],

    /// ESSID bytes
    #[field(role = salt, encoding = hex)]
    pub essid: Vec<u8>,

    /// Remaining WPA fields
    #[field(role = other, encoding = ascii)]
    pub extras: String,
}

impl Parse for WpaPmkid {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        let rest = parse::strip_prefix(input, "WPA*", 0)?;
        let mut parts = rest.splitn(6, '*');
        let kind = parts.next().unwrap_or_default();
        let pmkid = parts.next().ok_or_else(|| {
            parse::error(ParseErrorKind::InvalidLength, 4, "missing WPA PMKID field")
        })?;
        let access_point = parts.next().ok_or_else(|| {
            parse::error(
                ParseErrorKind::InvalidLength,
                4,
                "missing WPA access point field",
            )
        })?;
        let station = parts.next().ok_or_else(|| {
            parse::error(
                ParseErrorKind::InvalidLength,
                4,
                "missing WPA station field",
            )
        })?;
        let essid = parts.next().ok_or_else(|| {
            parse::error(ParseErrorKind::InvalidLength, 4, "missing WPA ESSID field")
        })?;
        let extras = parts.next().ok_or_else(|| {
            parse::error(
                ParseErrorKind::InvalidLength,
                4,
                "missing WPA trailing fields",
            )
        })?;

        if kind.len() != 2 || !kind.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                4,
                "WPA frame type must be two hex digits",
            ));
        }

        let essid_bytes = parse::decode_hex(essid, 4)?;

        Ok(Self {
            kind: kind.to_owned(),
            pmkid: parse::decode_hex_field::<16>(pmkid, 4, "pmkid")?,
            access_point: parse::decode_hex_field::<6>(access_point, 4, "access point")?,
            station: parse::decode_hex_field::<6>(station, 4, "station")?,
            essid: essid_bytes,
            extras: extras.to_owned(),
        })
    }
}

impl Render for WpaPmkid {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "WPA*{}*{}*{}*{}*{}*{}",
            self.kind,
            crate::format::hex(self.pmkid),
            crate::format::hex(self.access_point),
            crate::format::hex(self.station),
            crate::format::hex(&self.essid),
            self.extras
        )
    }
}
