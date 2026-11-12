//! SASL DIGEST-MD5, rendered as a `$sasl$` field sequence.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// SASL DIGEST-MD5 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "SASL DIGEST-MD5",
    slug = "sasl-digest-md5",
    hashcat = [37600],
)]
pub struct SaslDigestMd5 {
    /// SASL mechanism
    #[field(role = other, encoding = ascii)]
    pub mechanism: String,

    /// Authentication realm
    #[field(role = other, encoding = ascii)]
    pub realm: String,

    /// Username
    #[field(role = username, encoding = ascii)]
    pub username: String,

    /// Server nonce
    #[field(role = other, encoding = ascii)]
    pub nonce: String,

    /// Client nonce
    #[field(role = other, encoding = ascii)]
    pub client_nonce: String,

    /// Nonce count
    #[field(role = iterations, encoding = ascii)]
    pub nonce_count: String,

    /// Quality of protection
    #[field(role = other, encoding = ascii)]
    pub qop: String,

    /// Digest URI
    #[field(role = other, encoding = ascii)]
    pub digest_uri: String,

    /// Response digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 16],
}

impl Parse for SaslDigestMd5 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$sasl$", 0)?;
        let fields = parse::split_fields(rest, '$', 9)?;
        let (mechanism, _) = fields[0];
        let (realm, _) = fields[1];
        let (username, _) = fields[2];
        let (nonce, _) = fields[3];
        let (client_nonce, _) = fields[4];
        let (nonce_count, _) = fields[5];
        let (qop, _) = fields[6];
        let (digest_uri, _) = fields[7];
        let (digest, digest_offset) = fields[8];
        Ok(Self {
            mechanism: mechanism.to_owned(),
            realm: realm.to_owned(),
            username: username.to_owned(),
            nonce: nonce.to_owned(),
            client_nonce: client_nonce.to_owned(),
            nonce_count: nonce_count.to_owned(),
            qop: qop.to_owned(),
            digest_uri: digest_uri.to_owned(),
            digest: parse::decode_hex_field::<16>(digest, 6 + digest_offset, "digest")?,
        })
    }
}

impl Render for SaslDigestMd5 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$sasl${}${}${}${}${}${}${}${}${}",
            self.mechanism,
            self.realm,
            self.username,
            self.nonce,
            self.client_nonce,
            self.nonce_count,
            self.qop,
            self.digest_uri,
            crate::format::hex(self.digest)
        )
    }
}
