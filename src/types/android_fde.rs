//! Android FDE <= 4.3 hashes, rendered as
//! `$fde$16$<salt>$16$<digest>$<data>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// Android Full Disk Encryption hashes from before Android 4.4.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "Android FDE <= 4.3", slug = "android-fde", hashcat = [8800])]
pub struct AndroidFde {
    /// Sixteen-byte salt.
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 16],

    /// Sixteen-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 16],

    /// Encrypted master key and footer.
    #[field(role = ciphertext, encoding = hex)]
    pub data: Vec<u8>,
}

impl Parse for AndroidFde {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$fde$16$", 0)?;
        let (salt, rest, rest_offset) = parse::split_once(rest, '$', 9)?;
        let rest = parse::strip_prefix(rest, "16$", rest_offset)?;
        let (digest, data, data_offset) = parse::split_once(rest, '$', rest_offset + 3)?;
        Ok(Self {
            salt: parse::decode_hex_field::<16>(salt, 9, "salt")?,
            digest: parse::decode_hex_field::<16>(digest, rest_offset + 3, "digest")?,
            data: parse::decode_hex(data, data_offset)?,
        })
    }
}

impl Render for AndroidFde {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$fde$16${}$16${}${}",
            crate::format::hex(self.salt),
            crate::format::hex(self.digest),
            crate::format::hex(&self.data)
        )
    }
}
