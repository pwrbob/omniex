//! SunMD5, rendered as `$md5,rounds=<n>$<salt>$$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// SunMD5 password hash.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "SunMD5",
    slug = "sunmd5",
    hashcat = [3300],
    john = ["SunMD5"],
)]
pub struct SunMd5 {
    /// Round count.
    #[field(role = iterations, encoding = decimal)]
    pub rounds: u32,

    /// Salt string.
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// Digest string.
    #[field(role = digest, encoding = ascii)]
    pub digest: String,
}

impl Parse for SunMd5 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        let rest = parse::strip_prefix(input, "$md5,rounds=", 0)?;
        let (rounds, rest, rest_offset) = parse::split_once(rest, '$', 12)?;
        let rounds = rounds.parse::<u32>().map_err(|_| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                12,
                "invalid SunMD5 round count",
            )
        })?;
        let (salt, rest, _) = parse::split_once(rest, '$', rest_offset)?;
        let digest = rest.strip_prefix('$').unwrap_or(rest);

        if salt.is_empty() || salt.len() > 8 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                rest_offset,
                "SunMD5 salt must contain 1 to 8 characters",
            ));
        }

        Ok(Self {
            rounds,
            salt: salt.to_owned(),
            digest: digest.to_owned(),
        })
    }
}

impl Render for SunMd5 {
    fn render(&self, _opts: &RenderOptions) -> String {
        format!("$md5,rounds={}${}$${}", self.rounds, self.salt, self.digest)
    }
}
