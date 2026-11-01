//! Kerberos 5, etype 17/18, AS-REP, rendered as
//! `$krb5asrep$<etype>$<user>$<realm>$<checksum>$<ciphertext>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Kerberos 5, etype 17/18, AS-REP hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Kerberos 5, etype 17/18, AS-REP",
    slug = "krb5asrep-aes",
    hashcat = [32100, 32200],
    john = ["krb5asrep-aes-opencl"],
    modes_fn = krb5asrep_aes_modes,
)]
pub struct Krb5AsrepAes {
    /// Encryption type, 17 or 18.
    #[field(role = other, encoding = decimal)]
    pub etype: u8,

    /// Kerberos username.
    #[field(role = username, encoding = ascii)]
    pub username: String,

    /// Kerberos realm.
    #[field(role = other, encoding = ascii)]
    pub realm: String,

    /// Twelve-byte checksum.
    #[field(role = digest, encoding = hex)]
    pub checksum: [u8; 12],

    /// Hexadecimal ciphertext.
    #[field(role = ciphertext, encoding = hex)]
    pub ciphertext: Vec<u8>,
}

pub fn krb5asrep_aes_modes(value: &Krb5AsrepAes) -> Vec<crate::Mode> {
    match value.etype {
        17 => vec![crate::Mode::Hashcat(32100)],
        18 => vec![crate::Mode::Hashcat(32200)],
        _ => Vec::new(),
    }
}

impl Parse for Krb5AsrepAes {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$krb5asrep$", 0)?;
        let (etype, rest, _) = parse::split_once(rest, '$', 11)?;
        let fields = parse::split_fields(rest, '$', 4)?;
        let etype = etype.parse::<u8>().map_err(|_| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                11,
                "invalid Kerberos encryption type",
            )
        })?;
        if !matches!(etype, 17 | 18) {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                11,
                "Kerberos AS-REP encryption types are 17 or 18",
            ));
        }
        Ok(Self {
            etype,
            username: fields[0].0.to_owned(),
            realm: fields[1].0.to_owned(),
            checksum: parse::decode_hex_field::<12>(fields[2].0, fields[2].1, "checksum")?,
            ciphertext: parse::decode_hex(fields[3].0, fields[3].1)?,
        })
    }
}

impl Render for Krb5AsrepAes {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$krb5asrep${}${}${}${}${}",
            self.etype,
            self.username,
            self.realm,
            crate::format::hex(self.checksum),
            crate::format::hex(&self.ciphertext)
        )
    }
}
