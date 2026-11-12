//! SNMPv3 HMAC authentication, rendered as a `$SNMPv3$` field sequence.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// SNMPv3 HMAC authentication hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "SNMPv3 HMAC",
    slug = "snmpv3",
    hashcat = [25000, 25100, 25200, 26700, 26800, 26900, 27300], john = ["SNMP"],
    modes_fn = snmpv3_modes,
)]
pub struct Snmpv3 {
    /// Protocol variant
    #[field(role = other, encoding = decimal)]
    pub version: u8,

    /// Packet number
    #[field(role = other, encoding = ascii)]
    pub packet_number: String,

    /// Hexadecimal message bytes
    #[field(role = ciphertext, encoding = ascii)]
    pub message: String,

    /// Engine identifier
    #[field(role = other, encoding = ascii)]
    pub engine_id: String,

    /// Auth digest
    #[field(role = digest, encoding = hex)]
    pub digest: Vec<u8>,
}

pub fn snmpv3_modes(value: &Snmpv3) -> Vec<crate::Mode> {
    match value.version {
        0 => vec![crate::Mode::Hashcat(25000)],
        1 => vec![crate::Mode::Hashcat(25100)],
        2 => vec![crate::Mode::Hashcat(25200)],
        3 => vec![crate::Mode::Hashcat(26700)],
        4 => vec![crate::Mode::Hashcat(26800)],
        5 => vec![crate::Mode::Hashcat(26900)],
        6 => vec![crate::Mode::Hashcat(27300)],
        _ => Vec::new(),
    }
}

impl Parse for Snmpv3 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$SNMPv3$", 0)?;
        let fields = parse::split_fields(rest, '$', 5)?;
        Ok(Self {
            version: fields[0].0.parse::<u8>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    8,
                    "invalid SNMPv3 version",
                )
            })?,
            packet_number: fields[1].0.to_owned(),
            message: fields[2].0.to_owned(),
            engine_id: fields[3].0.to_owned(),
            digest: parse::decode_hex(fields[4].0, fields[4].1)?,
        })
    }
}

impl Render for Snmpv3 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$SNMPv3${}${}${}${}${}",
            self.version,
            self.packet_number,
            self.message,
            self.engine_id,
            crate::format::hex(&self.digest)
        )
    }
}
