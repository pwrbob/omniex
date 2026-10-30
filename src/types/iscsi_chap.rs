//! iSCSI CHAP MD5, rendered as `<digest>:<challenge>:<chap-id>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// iSCSI CHAP authentication hash.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "iSCSI CHAP",
    slug = "iscsi-chap",
    hashcat = [4800],
)]
pub struct IscsiChap {
    /// The 16-byte MD5 digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 16],

    /// CHAP challenge bytes.
    #[field(role = ciphertext, encoding = hex)]
    pub challenge: Vec<u8>,

    /// CHAP identifier bytes.
    #[field(role = other, encoding = hex)]
    pub chap_id: Vec<u8>,
}

impl Parse for IscsiChap {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        let (digest, rest, rest_offset) = parse::split_once(input, ':', 0)?;
        let (challenge, chap_id, chap_offset) = parse::split_once(rest, ':', rest_offset)?;

        Ok(Self {
            digest: parse::decode_hex_field::<16>(digest, 0, "digest")?,
            challenge: parse::decode_hex(challenge, rest_offset)?,
            chap_id: parse::decode_hex(chap_id, chap_offset)?,
        })
    }
}

impl Render for IscsiChap {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "{}:{}:{}",
            crate::format::hex(self.digest),
            crate::format::hex(&self.challenge),
            crate::format::hex(&self.chap_id)
        )
    }
}
