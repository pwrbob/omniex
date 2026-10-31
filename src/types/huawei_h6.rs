//! Huawei Comware `$h$6$` hashes, rendered as `$h$6$<salt>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// Huawei, H3C, and HPE Comware `$h$6$` hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "Huawei Comware $h$6$", slug = "huawei-h6", hashcat = [40002], john = ["h3c"])]
pub struct HuaweiH6 {
    /// ASCII salt.
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// Base64 digest.
    #[field(role = digest, encoding = base64)]
    pub digest: Vec<u8>,
}

impl Parse for HuaweiH6 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$h$6$", 0)?;
        let (salt, digest, digest_offset) = parse::split_once(rest, '$', 5)?;
        Ok(Self {
            salt: salt.to_owned(),
            digest: parse::decode_base64(digest, digest_offset)?,
        })
    }
}

impl Render for HuaweiH6 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$h$6${}${}", self.salt, crate::format::base64(&self.digest))
    }
}
