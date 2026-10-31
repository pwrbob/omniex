//! TCP-MD5 hashes, rendered as `$tcpmd5$<packet>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// TCP-MD5 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "TCP-MD5", slug = "tcp-md5", hashcat = [], john = ["tcp-md5"])]
pub struct TcpMd5 {
    /// Packet data.
    #[field(role = salt, encoding = ascii)]
    pub packet: String,

    /// Sixteen-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 16],
}

impl Parse for TcpMd5 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$tcpmd5$", 0)?;
        let (packet, digest, digest_offset) = parse::split_once(rest, '$', 9)?;
        Ok(Self {
            packet: packet.to_owned(),
            digest: parse::decode_hex_field::<16>(digest, digest_offset, "digest")?,
        })
    }
}

impl Render for TcpMd5 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$tcpmd5${}${}",
            self.packet,
            crate::format::hex(self.digest)
        )
    }
}
