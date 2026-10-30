//! Kerberos 5, etype 17, DB, rendered as `$krb5db$17$<user>$<realm>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// Kerberos 5, etype 17, DB hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Kerberos 5, etype 17, DB",
    slug = "krb5db17",
    hashcat = [28800],
)]
pub struct Krb5Db17 {
    /// Kerberos username.
    #[field(role = username, encoding = ascii)]
    pub username: String,

    /// Kerberos realm.
    #[field(role = other, encoding = ascii)]
    pub realm: String,

    /// The 16-byte key digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 16],
}

impl Parse for Krb5Db17 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$krb5db$17$", 0)?;
        let fields = parse::split_fields(rest, '$', 3)?;
        Ok(Self {
            username: fields[0].0.to_owned(),
            realm: fields[1].0.to_owned(),
            digest: parse::decode_hex_field::<16>(fields[2].0, fields[2].1, "digest")?,
        })
    }
}

impl Render for Krb5Db17 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$krb5db$17${}${}${}",
            self.username,
            self.realm,
            crate::format::hex(self.digest)
        )
    }
}
