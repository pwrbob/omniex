//! LastPass CLI hashes, rendered as
//! `$lpcli$<version>$<email>$<pin>$<encrypted key>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// LastPass CLI hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "LastPass CLI", slug = "lpcli", hashcat = [], john = ["lpcli"])]
pub struct Lpcli {
    /// Format version
    #[field(role = other, encoding = decimal)]
    pub version: u8,

    /// Account e-mail
    #[field(role = username, encoding = ascii)]
    pub email: String,

    /// PIN
    #[field(role = other, encoding = ascii)]
    pub pin: String,

    /// Encrypted key
    #[field(role = ciphertext, encoding = hex)]
    pub encrypted: Vec<u8>,

    /// 16-byte digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 16],
}

impl Parse for Lpcli {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$lpcli$", 0)?;
        let fields = parse::split_fields(rest, '$', 5)?;
        Ok(Self {
            version: fields[0].0.parse::<u8>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    7,
                    "invalid LP CLI version",
                )
            })?,
            email: fields[1].0.to_owned(),
            pin: fields[2].0.to_owned(),
            encrypted: parse::decode_hex(fields[3].0, fields[3].1)?,
            digest: parse::decode_hex_field::<16>(fields[4].0, fields[4].1, "digest")?,
        })
    }
}

impl Render for Lpcli {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$lpcli${}${}${}${}${}",
            self.version,
            self.email,
            self.pin,
            crate::format::hex(&self.encrypted),
            crate::format::hex(self.digest)
        )
    }
}
