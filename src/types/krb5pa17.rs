//! Kerberos 5, etype 17, Pre-Auth, rendered as `$krb5pa$17$<user>$<realm>$<ciphertext>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// Kerberos 5, etype 17, Pre-Auth hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Kerberos 5, etype 17, Pre-Auth",
    slug = "krb5pa17",
    hashcat = [19800],
)]
pub struct Krb5Pa17 {
    /// Kerberos username.
    #[field(role = username, encoding = ascii)]
    pub username: String,

    /// Kerberos realm.
    #[field(role = other, encoding = ascii)]
    pub realm: String,

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
        let fields = parse::split_fields(rest, '$', 3)?;
        Ok(Self {
            username: fields[0].0.to_owned(),
            realm: fields[1].0.to_owned(),
            ciphertext: parse::decode_hex(fields[2].0, fields[2].1)?,
        })
    }
}

impl Render for Krb5Pa17 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$krb5pa$17${}${}${}",
            self.username,
            self.realm,
            crate::format::hex(&self.ciphertext)
        )
    }
}
