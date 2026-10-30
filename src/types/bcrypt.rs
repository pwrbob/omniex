//! bcrypt, rendered as `$2a$<cost>$<salt><digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

const ALPHABET: &[u8] = b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// bcrypt password hash.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "bcrypt",
    slug = "bcrypt",
    hashcat = [3200],
    john = ["bcrypt"],
)]
pub struct Bcrypt {
    /// Version prefix, for example `$2a$`.
    #[field(role = other, encoding = ascii)]
    pub prefix: String,

    /// Cost parameter.
    #[field(role = iterations, encoding = decimal)]
    pub cost: u32,

    /// Twenty-two base64 salt characters.
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// Thirty-one base64 digest characters.
    #[field(role = digest, encoding = ascii)]
    pub digest: String,
}

impl Parse for Bcrypt {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        if input.len() != 60 || !input.is_ascii() {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                0,
                "bcrypt hash must be 60 ASCII characters",
            ));
        }

        let bytes = input.as_bytes();
        let prefix = &input[..4];
        if !matches!(prefix, "$2a$" | "$2b$" | "$2y$") {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                0,
                "expected `$2a$`, `$2b$`, or `$2y$` prefix",
            ));
        }

        if bytes[6] != b'$' {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                6,
                "expected `$` after the bcrypt cost",
            ));
        }

        let cost = input[4..6].parse::<u32>().map_err(|_| {
            parse::error(ParseErrorKind::InvalidCharacter, 4, "invalid bcrypt cost")
        })?;
        if !(4..=31).contains(&cost) {
            return Err(parse::error(
                ParseErrorKind::Other,
                4,
                "bcrypt cost must be between 04 and 31",
            ));
        }

        let salt = &input[7..29];
        let digest = &input[29..60];
        validate_base64(salt, 7, 4, "salt")?;
        validate_base64(digest, 29, 2, "digest")?;

        Ok(Self {
            prefix: prefix.to_owned(),
            cost,
            salt: salt.to_owned(),
            digest: digest.to_owned(),
        })
    }
}

fn validate_base64(
    value: &str,
    base: usize,
    trailing_zero_bits: u8,
    field: &str,
) -> Result<(), ParseError> {
    for (index, byte) in value.bytes().enumerate() {
        if !ALPHABET.contains(&byte) {
            return Err(parse::error(
                ParseErrorKind::InvalidBase64,
                base + index,
                format!("invalid bcrypt base64 character in {field}"),
            ));
        }
    }

    let Some(last) = value.bytes().last() else {
        return Err(parse::error(
            ParseErrorKind::InvalidLength,
            base,
            format!("{field} is empty"),
        ));
    };
    let index = ALPHABET
        .iter()
        .position(|byte| *byte == last)
        .expect("validated alphabet member") as u8;

    if index & ((1 << trailing_zero_bits) - 1) != 0 {
        return Err(parse::error(
            ParseErrorKind::InvalidCharacter,
            base + value.len() - 1,
            format!("non-zero padding bits in bcrypt {field}"),
        ));
    }

    Ok(())
}

impl Render for Bcrypt {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "{}{:02}${}{}",
            self.prefix, self.cost, self.salt, self.digest
        )
    }
}
