//! Telegram wallets, rendered as `$telegram$<version>*[<iterations>*]<salt>*<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Telegram wallet passcode hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Telegram",
    slug = "telegram",
    hashcat = [22301, 22600, 24500],
    modes_fn = telegram_modes,
)]
pub struct Telegram {
    /// Wallet format version, which selects the mode.
    #[field(role = other, encoding = decimal)]
    pub version: u8,

    /// Iteration count, zero when the version does not serialize one.
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// Hexadecimal salt.
    #[field(role = salt, encoding = hex)]
    pub salt: Vec<u8>,

    /// Hexadecimal digest.
    #[field(role = digest, encoding = hex)]
    pub digest: Vec<u8>,
}

pub fn telegram_modes(value: &Telegram) -> Vec<crate::Mode> {
    match value.version {
        0 => vec![crate::Mode::Hashcat(22301)],
        1 => vec![crate::Mode::Hashcat(22600)],
        2 => vec![crate::Mode::Hashcat(24500)],
        _ => Vec::new(),
    }
}

impl Parse for Telegram {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$telegram$", 0)?;
        let count = rest.split('*').count();
        if !(3..=4).contains(&count) {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                input.len(),
                "Telegram values have three or four fields",
            ));
        }
        let fields = parse::split_fields(rest, '*', count)?;
        let version = fields[0].0.parse::<u8>().map_err(|_| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                10,
                "invalid Telegram version",
            )
        })?;
        let (iterations, salt, digest) = if count == 4 {
            (
                fields[1].0.parse::<u32>().map_err(|_| {
                    parse::error(
                        ParseErrorKind::InvalidCharacter,
                        fields[1].1,
                        "invalid Telegram iteration count",
                    )
                })?,
                fields[2],
                fields[3],
            )
        } else {
            (0, fields[1], fields[2])
        };
        Ok(Self {
            version,
            iterations,
            salt: parse::decode_hex(salt.0, salt.1)?,
            digest: parse::decode_hex(digest.0, digest.1)?,
        })
    }
}

impl Render for Telegram {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        if self.version == 0 {
            format!(
                "$telegram$0*{}*{}",
                crate::format::hex(&self.salt),
                crate::format::hex(&self.digest)
            )
        } else {
            format!(
                "$telegram${}*{}*{}*{}",
                self.version,
                self.iterations,
                crate::format::hex(&self.salt),
                crate::format::hex(&self.digest)
            )
        }
    }
}
