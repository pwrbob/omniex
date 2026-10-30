//! Kerberos 5, etype 3, AS-REP, rendered as a Kerberos AS-REP field sequence.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// Kerberos 5, etype 3, AS-REP hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Kerberos 5, etype 3, AS-REP",
    slug = "krb5asrep3",
    hashcat = [38600],
)]
pub struct Krb5AsRep3 {
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

impl Parse for Krb5AsRep3 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$krb5asrep$3$", 0)?;
        let fields = parse::split_fields(rest, '$', 4)?;
        Ok(Self {
            username: fields[0].0.to_owned(),
            realm: fields[1].0.to_owned(),
            checksum: parse::decode_hex_field::<16>(fields[2].0, fields[2].1, "checksum")?,
            ciphertext: parse::decode_hex(fields[3].0, fields[3].1)?,
        })
    }
}

impl Render for Krb5AsRep3 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        if "3" == "23" {
            format!(
                "$krb5asrep$3${}@{}:{}${}",
                self.username,
                self.realm,
                crate::format::hex(self.checksum),
                crate::format::hex(&self.ciphertext)
            )
        } else {
            format!(
                "$krb5asrep$3${}${}${}${}",
                self.username,
                self.realm,
                crate::format::hex(self.checksum),
                crate::format::hex(&self.ciphertext)
            )
        }
    }
}
