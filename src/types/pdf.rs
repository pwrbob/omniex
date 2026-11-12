//! Password-protected PDF documents, rendered as
//! `$pdf$*<version>*<revision>*<key length>*<permissions>*<encrypt metadata>*<salt>*<data>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Password-protected PDF documents.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "PDF",
    slug = "pdf",
    hashcat = [10400, 10410, 10420, 10500, 10510, 10600, 10700, 25400], john = ["PDF"],
    modes_fn = pdf_modes,
)]
pub struct Pdf {
    /// Encryption version
    #[field(role = other, encoding = decimal)]
    pub version: u8,

    /// Encryption revision
    #[field(role = other, encoding = decimal)]
    pub revision: u8,

    /// Key length in bits
    #[field(role = other, encoding = decimal)]
    pub key_length: u32,

    /// Permission flags
    #[field(role = other, encoding = ascii)]
    pub permissions: String,

    /// Encrypt-metadata flag
    #[field(role = other, encoding = ascii)]
    pub encrypt_metadata: String,

    /// Hexadecimal salt
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// Remaining length-prefixed data
    #[field(role = other, encoding = ascii)]
    pub data: String,

    /// Collider RC4 key (may be empty)
    #[field(role = key, encoding = ascii)]
    pub rc4_key: String,
}

pub fn pdf_modes(value: &Pdf) -> Vec<crate::Mode> {
    match (value.version, value.revision) {
        (1, 2) if value.rc4_key.is_empty() => {
            vec![crate::Mode::Hashcat(10400), crate::Mode::Hashcat(10410)]
        }
        (1, 2) => vec![crate::Mode::Hashcat(10420)],
        (1, 3) => vec![crate::Mode::Hashcat(10510)],
        (2, 3) => vec![crate::Mode::Hashcat(10500), crate::Mode::Hashcat(25400)],
        (5, 5) => vec![crate::Mode::Hashcat(10600)],
        (5, 6) => vec![crate::Mode::Hashcat(10700)],
        _ => Vec::new(),
    }
}

impl Parse for Pdf {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$pdf$", 0)?;
        let mut fields = rest.splitn(7, '*');
        let mut next = |base: usize, name: &str| -> Result<(&str, usize), ParseError> {
            fields.next().map(|value| (value, base)).ok_or_else(|| {
                parse::error(
                    ParseErrorKind::InvalidLength,
                    5,
                    format!("missing PDF {name} field"),
                )
            })
        };

        let (version, _) = next(5, "version")?;
        let (revision, _) = next(7, "revision")?;
        let (key_length, key_length_offset) = next(9, "key length")?;
        let (permissions, _) = next(11, "permissions")?;
        let (encrypt_metadata, _) = next(13, "encrypt metadata")?;
        let (salt, _) = next(15, "salt")?;
        let (data, _) = next(17, "data")?;
        let (data, rc4_key) = data.split_once(':').unwrap_or((data, ""));

        let version = version.parse::<u8>().map_err(|_| {
            parse::error(ParseErrorKind::InvalidCharacter, 5, "invalid PDF version")
        })?;
        let revision = revision.parse::<u8>().map_err(|_| {
            parse::error(ParseErrorKind::InvalidCharacter, 7, "invalid PDF revision")
        })?;
        let key_length = key_length.parse::<u32>().map_err(|_| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                key_length_offset,
                "invalid PDF key length",
            )
        })?;

        Ok(Self {
            version,
            revision,
            key_length,
            permissions: permissions.to_owned(),
            encrypt_metadata: encrypt_metadata.to_owned(),
            salt: salt.to_owned(),
            data: data.to_owned(),
            rc4_key: rc4_key.to_owned(),
        })
    }
}

impl Render for Pdf {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        let mut value = format!(
            "$pdf${}*{}*{}*{}*{}*{}*{}",
            self.version,
            self.revision,
            self.key_length,
            self.permissions,
            self.encrypt_metadata,
            self.salt,
            self.data
        );
        if !self.rc4_key.is_empty() {
            value.push(':');
            value.push_str(&self.rc4_key);
        }
        value
    }
}
