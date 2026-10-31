//! 1Password mobile keychain hashes, rendered as a `$mobilekeychain$` field sequence.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// 1Password mobile keychain (1Password 8) hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "1Password mobile keychain",
    slug = "onepassword-mobile",
    hashcat = [31800]
)]
pub struct OnepasswordMobile {
    /// Account e-mail address.
    #[field(role = username, encoding = ascii)]
    pub email: String,

    /// Hexadecimal HKDF salt.
    #[field(role = salt, encoding = ascii)]
    pub hkdf_salt: String,

    /// Hexadecimal HKDF key.
    #[field(role = key, encoding = ascii)]
    pub hkdf_key: String,

    /// Iteration count.
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// Hexadecimal initialization vector.
    #[field(role = other, encoding = ascii)]
    pub iv: String,

    /// Hexadecimal ciphertext.
    #[field(role = ciphertext, encoding = ascii)]
    pub ciphertext: String,

    /// Sixteen-byte authentication tag.
    #[field(role = digest, encoding = ascii)]
    pub tag: String,
}

impl Parse for OnepasswordMobile {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$mobilekeychain$", 0)?;
        let fields = parse::split_fields(rest, '$', 7)?;
        Ok(Self {
            email: fields[0].0.to_owned(),
            hkdf_salt: fields[1].0.to_owned(),
            hkdf_key: fields[2].0.to_owned(),
            iterations: fields[3].0.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    fields[3].1,
                    "invalid 1Password iteration count",
                )
            })?,
            iv: fields[4].0.to_owned(),
            ciphertext: fields[5].0.to_owned(),
            tag: fields[6].0.to_owned(),
        })
    }
}

impl Render for OnepasswordMobile {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$mobilekeychain${}${}${}${}${}${}${}",
            self.email,
            self.hkdf_salt,
            self.hkdf_key,
            self.iterations,
            self.iv,
            self.ciphertext,
            self.tag
        )
    }
}
