//! Kerberos 5, etype 17, TGS-REP, rendered as `$krb5tgs$17$<user>$<realm>$<checksum>$<ciphertext>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// Kerberos 5, etype 17, TGS-REP hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Kerberos 5, etype 17, TGS-REP",
    slug = "krb5tgs17",
    hashcat = [19600],
)]
pub struct Krb5Tgs17 {
    /// Kerberos username.
    #[field(role = username, encoding = ascii)]
    pub username: String,

    /// Kerberos realm.
    #[field(role = other, encoding = ascii)]
    pub realm: String,

    /// The 12-byte checksum.
    #[field(role = digest, encoding = hex)]
    pub checksum: [u8; 12],

    /// Hexadecimal ciphertext.
    #[field(role = ciphertext, encoding = hex)]
    pub ciphertext: Vec<u8>,
}

impl Parse for Krb5Tgs17 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$krb5tgs$17$", 0)?;
        let fields = parse::split_fields(rest, '$', 4)?;
        Ok(Self {
            username: fields[0].0.to_owned(),
            realm: fields[1].0.to_owned(),
            checksum: parse::decode_hex_field::<12>(fields[2].0, fields[2].1, "checksum")?,
            ciphertext: parse::decode_hex(fields[3].0, fields[3].1)?,
        })
    }
}

impl Render for Krb5Tgs17 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$krb5tgs$17${}${}${}${}",
            self.username,
            self.realm,
            crate::format::hex(self.checksum),
            crate::format::hex(&self.ciphertext)
        )
    }
}
