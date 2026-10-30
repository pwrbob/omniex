//! Kerberos 5, etype 23, AS-REP, rendered as a Kerberos AS-REP field sequence.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// Kerberos 5, etype 23, AS-REP hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Kerberos 5, etype 23, AS-REP",
    slug = "krb5asrep23",
    hashcat = [18200],
)]
pub struct Krb5AsRep23 {
    /// Kerberos username.
    #[field(role = username, encoding = ascii)]
    pub username: String,

    /// Kerberos realm or domain.
    #[field(role = other, encoding = ascii)]
    pub realm: String,

    /// The 16-byte checksum.
    #[field(role = digest, encoding = hex)]
    pub checksum: [u8; 16],

    /// Hexadecimal ciphertext.
    #[field(role = ciphertext, encoding = hex)]
    pub ciphertext: Vec<u8>,
}

impl Parse for Krb5AsRep23 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$krb5asrep$23$", 0)?;
        let (username, realm, rest, rest_offset) = if rest.contains(':') {
            let (account, rest, rest_offset) = parse::split_once(rest, ':', 14)?;
            let (username, realm) = account.split_once('@').unwrap_or((account, ""));
            (username.to_owned(), realm.to_owned(), rest, rest_offset)
        } else {
            let fields = parse::split_fields(rest, '$', 2)?;
            let username = fields[0].0.to_owned();
            let realm = fields[1].0.to_owned();
            let rest_offset = fields[1].1 + realm.len() + 1;
            let rest = &rest[rest_offset..];
            (username, realm, rest, rest_offset)
        };
        let (checksum, ciphertext, ciphertext_offset) = parse::split_once(rest, '$', rest_offset)?;
        Ok(Self {
            username,
            realm,
            checksum: parse::decode_hex_field::<16>(checksum, rest_offset, "checksum")?,
            ciphertext: parse::decode_hex(ciphertext, ciphertext_offset)?,
        })
    }
}

impl Render for Krb5AsRep23 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$krb5asrep$23${}@{}:{}${}",
            self.username,
            self.realm,
            crate::format::hex(self.checksum),
            crate::format::hex(&self.ciphertext)
        )
    }
}
