//! VNC hashes, rendered as `$vnc$*<challenge>*<response>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// VNC hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "VNC", slug = "vnc", hashcat = [], john = ["VNC"])]
pub struct Vnc {
    /// 16-byte challenge
    #[field(role = salt, encoding = hex)]
    pub challenge: [u8; 16],

    /// 16-byte response
    #[field(role = digest, encoding = hex)]
    pub response: [u8; 16],
}

impl Parse for Vnc {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$vnc$*", 0)?;
        let (challenge, response, response_offset) = parse::split_once(rest, '*', 6)?;
        Ok(Self {
            challenge: parse::decode_hex_field::<16>(challenge, 6, "challenge")?,
            response: parse::decode_hex_field::<16>(response, response_offset, "response")?,
        })
    }
}

impl Render for Vnc {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$vnc$*{}*{}",
            crate::format::hex(self.challenge).to_uppercase(),
            crate::format::hex(self.response).to_uppercase()
        )
    }
}
