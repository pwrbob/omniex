//! iTunes backup hashes, rendered as
//! `$itunes_backup$*<version>*<wrapped key>*<iterations>*<salt>*<iterations 2>*<dpic>*<dpsl>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// iTunes backup password hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "iTunes backup",
    slug = "itunes-backup",
    hashcat = [14700, 14800], john = ["itunes-backup"],
    modes_fn = itunes_modes,
)]
pub struct ItunesBackup {
    /// Backup format version
    #[field(role = other, encoding = decimal)]
    pub version: u8,

    /// Wrapped protection key (hex)
    #[field(role = ciphertext, encoding = ascii)]
    pub wrapped_key: String,

    /// KDF iteration count
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// Double-protection salt (hex)
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// Double-protection iterations
    #[field(role = other, encoding = ascii)]
    pub iterations2: String,

    /// Double protection fields
    #[field(role = other, encoding = ascii)]
    pub extra: String,
}

pub fn itunes_modes(value: &ItunesBackup) -> Vec<crate::Mode> {
    match value.version {
        9 => vec![
            crate::Mode::Hashcat(14700),
            crate::Mode::John("itunes-backup"),
        ],
        10 => vec![
            crate::Mode::Hashcat(14800),
            crate::Mode::John("itunes-backup"),
        ],
        _ => Vec::new(),
    }
}

impl Parse for ItunesBackup {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$itunes_backup$*", 0)?;
        let parts: Vec<&str> = rest.split('*').collect();
        if parts.len() < 5 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                rest.len(),
                "iTunes backup hashes have at least five fields",
            ));
        }
        let version = parts[0].parse::<u8>().map_err(|_| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                10,
                "invalid iTunes backup version",
            )
        })?;
        if !matches!(version, 9 | 10) {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                10,
                "iTunes backup versions are 9 or 10",
            ));
        }
        let iterations = parts[2].parse::<u32>().map_err(|_| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                10,
                "invalid iTunes iteration count",
            )
        })?;
        Ok(Self {
            version,
            wrapped_key: parts[1].to_owned(),
            iterations,
            salt: parts[3].to_owned(),
            iterations2: parts[4].to_owned(),
            extra: parts[5..].join("*"),
        })
    }
}

impl Render for ItunesBackup {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$itunes_backup$*{}*{}*{}*{}*{}*{}",
            self.version,
            self.wrapped_key,
            self.iterations,
            self.salt,
            self.iterations2,
            self.extra
        )
    }
}
