//! TOTP hashes, rendered as colon-separated OTP code and timestamp pairs.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// TOTP (HMAC-SHA1) hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "TOTP (HMAC-SHA1)", slug = "totp", hashcat = [18100])]
pub struct Totp {
    /// OTP/timestamp pairs
    #[field(role = other, encoding = ascii)]
    pub pairs: String,
}

impl Parse for Totp {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let parts = input.split(':').collect::<Vec<_>>();
        if parts.len() % 2 != 0 || !(1..=4).contains(&(parts.len() / 2)) {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                0,
                "TOTP hashes contain one to four code and timestamp pairs",
            ));
        }
        for (index, part) in parts.iter().enumerate() {
            let valid = if index % 2 == 0 {
                part.len() == 6
            } else {
                (1..=20).contains(&part.len())
            };
            if !valid || !part.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(parse::error(
                    ParseErrorKind::InvalidCharacter,
                    0,
                    "TOTP codes are six digits and timestamps are up to twenty digits",
                ));
            }
        }
        Ok(Self {
            pairs: input.to_owned(),
        })
    }
}

impl Render for Totp {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        self.pairs.clone()
    }
}
