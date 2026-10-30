//! Kerberos 5, etype 3, TGS-REP, rendered as `$krb5tgs$3$*<user>$<realm>$<spn>*$<checksum>$<ciphertext>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Kerberos 5, etype 3, TGS-REP hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Kerberos 5, etype 3, TGS-REP",
    slug = "krb5tgs3",
    hashcat = [38500],
)]
pub struct Krb5Tgs3 {
    /// Kerberos username.
    #[field(role = username, encoding = ascii)]
    pub username: String,

    /// Kerberos realm.
    #[field(role = other, encoding = ascii)]
    pub realm: String,

    /// Service principal name.
    #[field(role = other, encoding = ascii)]
    pub spn: String,

    /// The 16-byte checksum.
    #[field(role = digest, encoding = hex)]
    pub checksum: [u8; 16],

    /// Hexadecimal ciphertext.
    #[field(role = ciphertext, encoding = hex)]
    pub ciphertext: Vec<u8>,
}

impl Parse for Krb5Tgs3 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$krb5tgs$3$", 0)?;
        let Some(account) = rest.strip_prefix('*') else {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                "$krb5tgs$3$".len(),
                "expected `*` before Kerberos account information",
            ));
        };
        let Some(end) = account.find("*$") else {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                "$krb5tgs$3$*".len(),
                "expected `*$` after Kerberos account information",
            ));
        };
        let (account, rest) = account.split_at(end);
        let rest = &rest[2..];
        let account_fields = parse::split_fields(account, '$', 3)?;
        let (checksum, ciphertext, ciphertext_offset) = parse::split_once(rest, '$', 0)?;

        Ok(Self {
            username: account_fields[0].0.to_owned(),
            realm: account_fields[1].0.to_owned(),
            spn: account_fields[2].0.to_owned(),
            checksum: parse::decode_hex_field::<16>(checksum, 0, "checksum")?,
            ciphertext: parse::decode_hex(ciphertext, ciphertext_offset)?,
        })
    }
}

impl Render for Krb5Tgs3 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$krb5tgs$3$*{}${}${}*${}${}",
            self.username,
            self.realm,
            self.spn,
            crate::format::hex(self.checksum),
            crate::format::hex(&self.ciphertext)
        )
    }
}
