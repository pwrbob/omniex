//! NetMD5 hashes, rendered as `<packet>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// NetMD5 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "NetMD5", slug = "net-md5", hashcat = [], john = ["net-md5"])]
pub struct NetMd5 {
    /// Packet data.
    #[field(role = salt, encoding = ascii)]
    pub packet: String,

    /// Sixteen-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 16],
}

impl Parse for NetMd5 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let (packet, digest, digest_offset) = parse::split_once(input, '$', 0)?;
        Ok(Self {
            packet: packet.to_owned(),
            digest: parse::decode_hex_field::<16>(digest, digest_offset, "digest")?,
        })
    }
}

impl Render for NetMd5 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("{}${}", self.packet, crate::format::hex(self.digest))
    }
}
