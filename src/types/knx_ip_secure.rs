//! KNX IP Secure device authentication code.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// KNX IP Secure device authentication codes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "KNX IP Secure - Device Authentication Code",
    slug = "knx-ip-secure",
    hashcat = [25900],
)]
pub struct KnxIpSecure {
    /// Secure session identifier bytes, serialized as hex.
    #[field(role = other, encoding = hex)]
    pub session_id: Vec<u8>,

    /// The 32-byte XORed public value.
    #[field(role = other, encoding = hex)]
    pub public_value: [u8; 32],

    /// The 16-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 16],
}

impl Parse for KnxIpSecure {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$knx-ip-secure-device-authentication-code$*", 0)?;
        let fields = parse::split_fields(rest, '*', 3)?;
        if fields[0].0.len() != 4 || !fields[0].0.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                43,
                "KNX session identifier must be four hex digits",
            ));
        }
        Ok(Self {
            session_id: parse::decode_hex(fields[0].0, 43)?,
            public_value: parse::decode_hex_field::<32>(fields[1].0, fields[1].1, "public value")?,
            digest: parse::decode_hex_field::<16>(fields[2].0, fields[2].1, "digest")?,
        })
    }
}

impl Render for KnxIpSecure {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$knx-ip-secure-device-authentication-code$*{}*{}*{}",
            crate::format::hex(&self.session_id),
            crate::format::hex(self.public_value),
            crate::format::hex(self.digest)
        )
    }
}
