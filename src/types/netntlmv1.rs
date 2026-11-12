//! NetNTLMv1, rendered as `user::domain:lm_response:nt_response:challenge`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// NetNTLMv1 challenge-response.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "NetNTLMv1",
    slug = "netntlmv1",
    hashcat = [5500, 27000],
)]
pub struct NetNtlmV1 {
    /// User name
    #[field(role = username, encoding = ascii)]
    pub username: String,

    /// Domain or workgroup
    #[field(role = other, encoding = ascii)]
    pub domain: String,

    /// LM response (empty for NT-only)
    #[field(role = ciphertext, encoding = hex)]
    pub lm_response: Vec<u8>,

    /// NT response
    #[field(role = ciphertext, encoding = hex)]
    pub nt_response: [u8; 24],

    /// 8-byte server challenge
    #[field(role = ciphertext, encoding = hex)]
    pub challenge: [u8; 8],
}

impl Parse for NetNtlmV1 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        let fields = parse::split_fields(input, ':', 6)?;
        let username = fields[0].0;
        let domain = fields[2].0;
        let lm = fields[3];
        let nt = fields[4];
        let challenge = fields[5];

        if !fields[1].0.is_empty() {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                fields[1].1,
                "the NetNTLM separator must be `::`",
            ));
        }

        parse::check_text_length(username, fields[0].1, 60, "username")?;
        parse::check_text_length(domain, fields[2].1, 45, "domain")?;
        parse::check_hex(lm.0, lm.1, "LM response")?;
        if !lm.0.is_empty() && lm.0.len() != 48 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                lm.1,
                "LM response must be empty or 48 hexadecimal digits",
            ));
        }

        Ok(Self {
            username: username.to_owned(),
            domain: domain.to_owned(),
            lm_response: parse::decode_hex(lm.0, lm.1)?,
            nt_response: parse::decode_hex_field::<24>(nt.0, nt.1, "NT response")?,
            challenge: parse::decode_hex_field::<8>(challenge.0, challenge.1, "challenge")?,
        })
    }
}

impl Render for NetNtlmV1 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "{}::{}:{}:{}:{}",
            self.username,
            self.domain,
            crate::format::hex(&self.lm_response),
            crate::format::hex(self.nt_response),
            crate::format::hex(self.challenge)
        )
    }
}
