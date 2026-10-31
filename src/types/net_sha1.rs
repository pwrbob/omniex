//! NetSHA1 hashes, rendered as `$netsha1$<packet>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// NetSHA1 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "NetSHA1", slug = "net-sha1", hashcat = [], john = ["net-sha1"])]
pub struct NetSha1 {
    /// Packet data.
    #[field(role = salt, encoding = ascii)]
    pub packet: String,

    /// Twenty-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 20],
}

impl Parse for NetSha1 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$netsha1$", 0)?;
        let (packet, digest, digest_offset) = parse::split_once(rest, '$', 9)?;
        Ok(Self {
            packet: packet.to_owned(),
            digest: parse::decode_hex_field::<20>(digest, digest_offset, "digest")?,
        })
    }
}

impl Render for NetSha1 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$netsha1${}${}",
            self.packet,
            crate::format::hex(self.digest)
        )
    }
}
