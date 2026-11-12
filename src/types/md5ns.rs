//! md5ns hashes, rendered as `<user>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Netscape / md5ns hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "md5ns", slug = "md5ns", hashcat = [], john = ["md5ns"])]
pub struct Md5ns {
    /// User name.
    #[field(role = username, encoding = ascii)]
    pub username: String,

    /// Encoded digest.
    #[field(role = digest, encoding = ascii)]
    pub digest: String,
}

const FIXED_CHARS: [(usize, u8); 6] = [
    (0, b'n'),
    (6, b'r'),
    (12, b'c'),
    (17, b's'),
    (23, b't'),
    (29, b'n'),
];

impl Parse for Md5ns {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let (username, digest, digest_offset) = parse::split_once(input, '$', 0)?;
        if username.is_empty() {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                0,
                "missing md5ns user name",
            ));
        }
        parse::check_text_length(username, 0, 32, "md5ns user name")?;
        if digest.len() != 30 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                digest_offset,
                "md5ns digests are 30 base64 characters",
            ));
        }
        for (index, expected) in FIXED_CHARS {
            if digest.as_bytes()[index] != expected {
                return Err(parse::error(
                    ParseErrorKind::InvalidCharacter,
                    digest_offset + index,
                    "md5ns digest does not have the Netscreen layout",
                ));
            }
        }
        if !digest
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/')
        {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                digest_offset,
                "md5ns digest is not base64",
            ));
        }
        Ok(Self {
            username: username.to_owned(),
            digest: digest.to_owned(),
        })
    }
}

impl Render for Md5ns {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("{}${}", self.username, self.digest)
    }
}
