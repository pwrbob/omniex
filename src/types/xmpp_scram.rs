//! XMPP SCRAM-SHA1 hashes, rendered as
//! `$xmpp-scram$<version>$<iterations>$<salt length>$<salt>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// XMPP SCRAM-SHA1 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "XMPP SCRAM", slug = "xmpp-scram", hashcat = [40052], john = ["SCRAM-PBKDF2-SHA1"])]
pub struct XmppScram {
    /// Format version
    #[field(role = other, encoding = decimal)]
    pub version: u8,

    /// Iteration count
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// Salt size in bytes
    #[field(role = other, encoding = decimal)]
    pub salt_size: u8,

    /// Hexadecimal salt
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// Hexadecimal digest
    #[field(role = digest, encoding = ascii)]
    pub digest: String,
}

impl Parse for XmppScram {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$xmpp-scram$", 0)?;
        let fields = parse::split_fields(rest, '$', 5)?;
        let number = |field: (&str, usize), name: &str| -> Result<u32, ParseError> {
            field.0.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    field.1,
                    format!("invalid XMPP SCRAM {name}"),
                )
            })
        };
        Ok(Self {
            version: u8::try_from(number(fields[0], "version")?).map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    fields[0].1,
                    "invalid version",
                )
            })?,
            iterations: number(fields[1], "iterations")?,
            salt_size: u8::try_from(number(fields[2], "salt size")?).map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    fields[2].1,
                    "invalid salt size",
                )
            })?,
            salt: fields[3].0.to_owned(),
            digest: fields[4].0.to_owned(),
        })
    }
}

impl Render for XmppScram {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$xmpp-scram${}${}${}${}${}",
            self.version, self.iterations, self.salt_size, self.salt, self.digest
        )
    }
}
