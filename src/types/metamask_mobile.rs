//! MetaMask Mobile wallet hashes, rendered as
//! `$metamaskMobile$<salt>$<iv>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// MetaMask Mobile wallet hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "MetaMask Mobile Wallet",
    slug = "metamask-mobile",
    hashcat = [31900]
)]
pub struct MetamaskMobile {
    /// Base64 salt.
    #[field(role = salt, encoding = base64)]
    pub salt: Vec<u8>,

    /// Sixteen-byte initialization vector.
    #[field(role = other, encoding = hex)]
    pub iv: [u8; 16],

    /// Base64 digest.
    #[field(role = digest, encoding = base64)]
    pub digest: Vec<u8>,
}

impl Parse for MetamaskMobile {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$metamaskMobile$", 0)?;
        let fields = parse::split_fields(rest, '$', 3)?;
        Ok(Self {
            salt: parse::decode_base64(fields[0].0, fields[0].1)?,
            iv: parse::decode_hex_field::<16>(fields[1].0, fields[1].1, "iv")?,
            digest: parse::decode_base64(fields[2].0, fields[2].1)?,
        })
    }
}

impl Render for MetamaskMobile {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$metamaskMobile${}${}${}",
            crate::format::base64(&self.salt),
            crate::format::hex(self.iv),
            crate::format::base64(&self.digest)
        )
    }
}
