//! Windows DPAPI master key hashes, rendered as
//! `$DPAPImk$*<version>*<context>*<SID>*<cipher>*<hash>*<rounds>*<salt>*<contents length>*<contents>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Windows DPAPI master key hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "DPAPI masterkey",
    slug = "dpapi",
    hashcat = [15300, 15310, 15900, 15910], john = ["DPAPImk"],
    modes_fn = dpapi_modes,
)]
pub struct Dpapi {
    /// Master key format version.
    #[field(role = other, encoding = decimal)]
    pub version: u8,

    /// Credential history context.
    #[field(role = other, encoding = decimal)]
    pub context: u8,

    /// Security identifier of the account.
    #[field(role = username, encoding = ascii)]
    pub sid: String,

    /// Cipher algorithm name.
    #[field(role = other, encoding = ascii)]
    pub cipher: String,

    /// Hash algorithm name.
    #[field(role = other, encoding = ascii)]
    pub hash: String,

    /// Key derivation round count.
    #[field(role = iterations, encoding = decimal)]
    pub rounds: u32,

    /// Sixteen-byte salt.
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 16],

    /// Encrypted blob length in hex digits.
    #[field(role = other, encoding = decimal)]
    pub contents_size: u32,

    /// Encrypted master key blob.
    #[field(role = ciphertext, encoding = hex)]
    pub contents: Vec<u8>,
}

pub fn dpapi_modes(value: &Dpapi) -> Vec<crate::Mode> {
    match (value.version, value.context) {
        (1, 1 | 2) => vec![crate::Mode::Hashcat(15300), crate::Mode::John("DPAPImk")],
        (1, 3) => vec![crate::Mode::Hashcat(15310), crate::Mode::John("DPAPImk")],
        (2, 1 | 2) => vec![crate::Mode::Hashcat(15900), crate::Mode::John("DPAPImk")],
        (2, 3) => vec![crate::Mode::Hashcat(15910), crate::Mode::John("DPAPImk")],
        _ => Vec::new(),
    }
}

impl Parse for Dpapi {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$DPAPImk$", 0)?;
        let fields = parse::split_fields(rest, '*', 9)?;
        fn number(value: &str, offset: usize, name: &str) -> Result<u32, ParseError> {
            value.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    offset,
                    format!("invalid DPAPI {name}"),
                )
            })
        }

        let contents = parse::decode_hex(fields[8].0, fields[8].1)?;
        let contents_size = number(fields[7].0, fields[7].1, "contents size")?;
        if contents.len() * 2 != contents_size as usize {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                fields[8].1,
                "DPAPI contents length does not match its header",
            ));
        }

        Ok(Self {
            version: u8::try_from(number(fields[0].0, fields[0].1, "version")?).map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    11,
                    "invalid DPAPI version",
                )
            })?,
            context: u8::try_from(number(fields[1].0, fields[1].1, "context")?).map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    13,
                    "invalid DPAPI context",
                )
            })?,
            sid: fields[2].0.to_owned(),
            cipher: fields[3].0.to_owned(),
            hash: fields[4].0.to_owned(),
            rounds: number(fields[5].0, fields[5].1, "rounds")?,
            salt: parse::decode_hex_field::<16>(fields[6].0, fields[6].1, "salt")?,
            contents_size,
            contents,
        })
    }
}

impl Render for Dpapi {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$DPAPImk${}*{}*{}*{}*{}*{}*{}*{}*{}",
            self.version,
            self.context,
            self.sid,
            self.cipher,
            self.hash,
            self.rounds,
            crate::format::hex(self.salt),
            self.contents_size,
            crate::format::hex(&self.contents)
        )
    }
}
