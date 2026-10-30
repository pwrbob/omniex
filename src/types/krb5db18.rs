//! Kerberos 5, etype 18, DB, rendered as `$krb5db$18$<user>$<realm>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// Kerberos 5, etype 18, DB hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Kerberos 5, etype 18, DB",
    slug = "krb5db18",
    hashcat = [28900],
)]
pub struct Krb5Db18 {
    /// Kerberos username.
    #[field(role = username, encoding = ascii)]
    pub username: String,

    /// Kerberos realm.
    #[field(role = other, encoding = ascii)]
    pub realm: String,

    /// The 32-byte key digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 32],
}

impl Parse for Krb5Db18 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$krb5db$18$", 0)?;
        let fields = parse::split_fields(rest, '$', 3)?;
        Ok(Self {
            username: fields[0].0.to_owned(),
            realm: fields[1].0.to_owned(),
            digest: parse::decode_hex_field::<32>(fields[2].0, fields[2].1, "digest")?,
        })
    }
}

impl Render for Krb5Db18 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$krb5db$18${}${}${}",
            self.username,
            self.realm,
            crate::format::hex(self.digest)
        )
    }
}
