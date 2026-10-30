//! OSPFv2/RIPv2 MD5, rendered as `$netmd5$<packet>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// OSPFv2/RIPv2 MD5 authentication hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "OSPFv2/RIPv2 MD5 authentication",
    slug = "ospf-md5",
    hashcat = [40001],
)]
pub struct OspfMd5 {
    /// Hexadecimal packet bytes.
    #[field(role = other, encoding = hex)]
    pub packet: Vec<u8>,

    /// The 16-byte MD5 digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 16],
}

impl Parse for OspfMd5 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$netmd5$", 0)?;
        let (packet, digest, digest_offset) = parse::split_once(rest, '$', 8)?;
        Ok(Self {
            packet: parse::decode_hex(packet, 8)?,
            digest: parse::decode_hex_field::<16>(digest, 8 + digest_offset, "digest")?,
        })
    }
}

impl Render for OspfMd5 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$netmd5${}${}",
            crate::format::hex(&self.packet),
            crate::format::hex(self.digest)
        )
    }
}
