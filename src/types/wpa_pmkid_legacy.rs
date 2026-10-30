//! WPA PMKID hashes in the older colon-separated format.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// WPA PMKID hashes using the legacy serialization.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "WPA-PMKID (legacy)",
    slug = "wpa-pmkid-legacy",
    hashcat = [16800, 16801],
    modes_fn = wpa_pmkid_legacy_modes,
)]
pub struct WpaPmkidLegacy {
    /// The 16-byte PMKID.
    #[field(role = digest, encoding = hex)]
    pub pmkid: [u8; 16],

    /// Access point MAC address.
    #[field(role = other, encoding = hex)]
    pub access_point: [u8; 6],

    /// Station MAC address.
    #[field(role = other, encoding = hex)]
    pub station: [u8; 6],

    /// ESSID bytes, empty when the hash does not serialize an ESSID.
    #[field(role = salt, encoding = hex)]
    pub essid: Vec<u8>,
}

pub fn wpa_pmkid_legacy_modes(value: &WpaPmkidLegacy) -> Vec<crate::Mode> {
    if value.essid.is_empty() {
        vec![crate::Mode::Hashcat(16801)]
    } else {
        vec![crate::Mode::Hashcat(16800)]
    }
}

impl Parse for WpaPmkidLegacy {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let count = input.split(':').count();
        if !(3..=4).contains(&count) {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                input.len(),
                "legacy WPA PMKID values have three or four fields",
            ));
        }
        let fields = parse::split_fields(input, ':', count)?;
        let essid = if fields.len() == 4 {
            parse::decode_hex(fields[3].0, fields[3].1)?
        } else {
            Vec::new()
        };
        Ok(Self {
            pmkid: parse::decode_hex_field::<16>(fields[0].0, fields[0].1, "pmkid")?,
            access_point: parse::decode_hex_field::<6>(fields[1].0, fields[1].1, "access point")?,
            station: parse::decode_hex_field::<6>(fields[2].0, fields[2].1, "station")?,
            essid,
        })
    }
}

impl Render for WpaPmkidLegacy {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        if self.essid.is_empty() {
            format!(
                "{}:{}:{}",
                crate::format::hex(self.pmkid),
                crate::format::hex(self.access_point),
                crate::format::hex(self.station)
            )
        } else {
            format!(
                "{}:{}:{}:{}",
                crate::format::hex(self.pmkid),
                crate::format::hex(self.access_point),
                crate::format::hex(self.station),
                crate::format::hex(&self.essid)
            )
        }
    }
}
