//! BLAKE2b-512 with an ASCII salt, rendered as `$BLAKE2$<digest>:<salt>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// BLAKE2b-512 with one ASCII salt.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Salted BLAKE2b-512",
    slug = "salted-blake2b-512",
    hashcat = [610, 620],
    modes_fn = salted_blake2b_modes,
)]
pub struct SaltedBlake2b512 {
    /// The 64-byte BLAKE2b digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 64],

    /// Salt used by the attack mode.
    #[field(role = salt, encoding = ascii)]
    pub salt: String,
}

impl Parse for SaltedBlake2b512 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        let rest = parse::strip_prefix(input, "$BLAKE2$", 0)?;
        let (digest, salt, salt_offset) = parse::split_once(rest, ':', 8)?;

        if salt.contains(':') {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                salt_offset + salt.find(':').expect("found"),
                "salt must not contain `:`",
            ));
        }

        Ok(Self {
            digest: parse::decode_hex_field::<64>(digest, 8, "digest")?,
            salt: salt.to_owned(),
        })
    }
}

pub fn salted_blake2b_modes(value: &SaltedBlake2b512) -> Vec<crate::Mode> {
    if value.salt.chars().count() > 127 {
        return Vec::new();
    }

    SaltedBlake2b512::DESCRIPTOR.all_modes.to_vec()
}

impl Render for SaltedBlake2b512 {
    fn render(&self, _opts: &RenderOptions) -> String {
        format!("$BLAKE2${}:{}", crate::format::hex(self.digest), self.salt)
    }
}
