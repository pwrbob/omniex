//! Kerberos 5, etype 17, Pre-Auth, rendered as
//! `$krb5pa$17$<user>$<realm>$<ciphertext>` for hashcat and
//! `$krb5pa$17$<user>$<realm>$<salt>$<ciphertext>` for John.

use crate::parse;
use crate::{
    HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions, Tool,
};

/// Kerberos 5, etype 17, Pre-Auth hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Kerberos 5, etype 17, Pre-Auth",
    slug = "krb5pa17",
    hashcat = [19800],
    john = ["krb5pa-sha1"],
)]
pub struct Krb5Pa17 {
    /// Kerberos username.
    #[field(role = username, encoding = ascii)]
    pub username: String,

    /// Kerberos realm.
    #[field(role = other, encoding = ascii)]
    pub realm: String,

    /// Pre-authentication salt. Empty means the realm and username are used.
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// Hexadecimal ciphertext.
    #[field(role = ciphertext, encoding = hex)]
    pub ciphertext: Vec<u8>,
}

impl Parse for Krb5Pa17 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$krb5pa$17$", 0)?;
        let fields: Vec<&str> = rest.split('$').collect();
        let (username, realm, salt, ciphertext, offset) = match fields.as_slice() {
            [username, realm, ciphertext] => (
                *username,
                *realm,
                "",
                *ciphertext,
                fields[0].len() + 1 + fields[1].len() + 1,
            ),
            [username, realm, salt, ciphertext] => (
                *username,
                *realm,
                *salt,
                *ciphertext,
                fields[0].len() + 1 + fields[1].len() + 1 + fields[2].len() + 1,
            ),
            _ => {
                return Err(parse::error(
                    ParseErrorKind::InvalidLength,
                    0,
                    "expected user, realm, optional salt, and ciphertext",
                ));
            }
        };
        Ok(Self {
            username: username.to_owned(),
            realm: realm.to_owned(),
            salt: salt.to_owned(),
            ciphertext: parse::decode_hex(ciphertext, 11 + offset)?,
        })
    }
}

impl Render for Krb5Pa17 {
    fn render_value(&self, opts: &RenderOptions) -> String {
        let ciphertext = crate::format::hex(&self.ciphertext);
        if opts.tool == Tool::John {
            return format!(
                "$krb5pa$17${}${}${}${}",
                self.username, self.realm, self.salt, ciphertext
            );
        }
        if self.salt.is_empty() {
            format!("$krb5pa$17${}${}${}", self.username, self.realm, ciphertext)
        } else {
            format!(
                "$krb5pa$17${}${}${}${}",
                self.username, self.realm, self.salt, ciphertext
            )
        }
    }
}
