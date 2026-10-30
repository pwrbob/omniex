//! NetNTLMv2, rendered as `user::domain:challenge:nt_proof:blob`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// NetNTLMv2 challenge-response.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "NetNTLMv2",
    slug = "netntlmv2",
    hashcat = [5600, 27100],
    john = ["netntlmv2"],
)]
pub struct NetNtlmV2 {
    /// User name from the authentication exchange.
    #[field(role = username, encoding = ascii)]
    pub username: String,

    /// Domain or workgroup from the authentication exchange.
    #[field(role = other, encoding = ascii)]
    pub domain: String,

    /// Eight-byte server challenge.
    #[field(role = ciphertext, encoding = hex)]
    pub challenge: [u8; 8],

    /// Sixteen-byte NT proof string.
    #[field(role = ciphertext, encoding = hex)]
    pub nt_proof: [u8; 16],

    /// Variable-length NTLMv2 client blob.
    #[field(role = salt, encoding = hex)]
    pub blob: Vec<u8>,
}

impl Parse for NetNtlmV2 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        let fields = parse::split_fields(input, ':', 6)?;
        let username = fields[0].0;
        let domain = fields[2].0;
        let challenge = fields[3];
        let proof = fields[4];
        let blob = fields[5];

        if !fields[1].0.is_empty() {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                fields[1].1,
                "the NetNTLM separator must be `::`",
            ));
        }

        parse::check_text_length(username, fields[0].1, 60, "username")?;
        parse::check_text_length(domain, fields[2].1, 45, "domain")?;
        parse::check_hex(blob.0, blob.1, "blob")?;
        if blob.0.is_empty() || blob.0.len() > 1024 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                blob.1,
                "blob must contain between 1 and 512 bytes",
            ));
        }

        Ok(Self {
            username: username.to_owned(),
            domain: domain.to_owned(),
            challenge: parse::decode_hex_field::<8>(challenge.0, challenge.1, "challenge")?,
            nt_proof: parse::decode_hex_field::<16>(proof.0, proof.1, "NT proof")?,
            blob: parse::decode_hex(blob.0, blob.1)?,
        })
    }
}

impl Render for NetNtlmV2 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "{}::{}:{}:{}:{}",
            self.username,
            self.domain,
            crate::format::hex(self.challenge),
            crate::format::hex(self.nt_proof),
            crate::format::hex(&self.blob)
        )
    }
}
