//! IKE-PSK MD5 in the nine-field hashcat serialization.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// IKE-PSK MD5 challenge-response.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "IKE-PSK MD5",
    slug = "ike-psk-md5",
    hashcat = [5300],
)]
pub struct IkePskMd5 {
    /// First fragment of the IKE exchange message.
    #[field(role = ciphertext, encoding = hex)]
    pub message_0: Vec<u8>,

    /// Second fragment of the IKE exchange message.
    #[field(role = ciphertext, encoding = hex)]
    pub message_1: Vec<u8>,

    /// Third fragment of the IKE exchange message.
    #[field(role = ciphertext, encoding = hex)]
    pub message_2: Vec<u8>,

    /// Fourth fragment of the IKE exchange message.
    #[field(role = ciphertext, encoding = hex)]
    pub message_3: Vec<u8>,

    /// Fifth fragment of the IKE exchange message.
    #[field(role = ciphertext, encoding = hex)]
    pub message_4: Vec<u8>,

    /// Sixth fragment of the IKE exchange message.
    #[field(role = ciphertext, encoding = hex)]
    pub message_5: Vec<u8>,

    /// First responder nonce fragment.
    #[field(role = salt, encoding = hex)]
    pub nonce_0: Vec<u8>,

    /// Second responder nonce fragment.
    #[field(role = salt, encoding = hex)]
    pub nonce_1: Vec<u8>,

    /// Sixteen-byte MD5 authentication digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 16],
}

impl Parse for IkePskMd5 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        let fields = parse::split_fields(input, ':', 9)?;
        let mut message = Vec::with_capacity(6);
        for (index, (value, offset)) in fields.iter().take(6).enumerate() {
            parse::check_hex(value, *offset, "message")?;
            if value.len() > 1024 {
                return Err(parse::error(
                    ParseErrorKind::InvalidLength,
                    *offset,
                    format!("message fragment {index} is too long"),
                ));
            }
            message.push(parse::decode_hex(value, *offset)?);
        }

        let mut nonce = Vec::with_capacity(2);
        for (index, (value, offset)) in fields.iter().skip(6).take(2).enumerate() {
            parse::check_hex(value, *offset, "nonce")?;
            if value.len() > 128 {
                return Err(parse::error(
                    ParseErrorKind::InvalidLength,
                    *offset,
                    format!("nonce fragment {index} is too long"),
                ));
            }
            nonce.push(parse::decode_hex(value, *offset)?);
        }

        if message.iter().map(Vec::len).sum::<usize>() >= 512 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                0,
                "IKE message must be shorter than 512 bytes",
            ));
        }
        if nonce.iter().map(Vec::len).sum::<usize>() >= 64 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                0,
                "IKE nonce must be shorter than 64 bytes",
            ));
        }

        let (digest, digest_offset) = fields[8];
        Ok(Self {
            message_0: message[0].clone(),
            message_1: message[1].clone(),
            message_2: message[2].clone(),
            message_3: message[3].clone(),
            message_4: message[4].clone(),
            message_5: message[5].clone(),
            nonce_0: nonce[0].clone(),
            nonce_1: nonce[1].clone(),
            digest: parse::decode_hex_field::<16>(digest, digest_offset, "digest")?,
        })
    }
}

impl Render for IkePskMd5 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "{}:{}:{}:{}:{}:{}:{}:{}:{}",
            crate::format::hex(&self.message_0),
            crate::format::hex(&self.message_1),
            crate::format::hex(&self.message_2),
            crate::format::hex(&self.message_3),
            crate::format::hex(&self.message_4),
            crate::format::hex(&self.message_5),
            crate::format::hex(&self.nonce_0),
            crate::format::hex(&self.nonce_1),
            crate::format::hex(self.digest)
        )
    }
}
