//! SIP digest authentication hashes, rendered as a `$sip$` field sequence.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// SIP digest authentication (MD5) hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "SIP digest authentication",
    slug = "sip-digest",
    hashcat = [11400], john = ["SIP"]
)]
pub struct SipDigest {
    /// First unused field.
    #[field(role = other, encoding = ascii)]
    pub unused1: String,

    /// Second unused field.
    #[field(role = other, encoding = ascii)]
    pub unused2: String,

    /// SIP user name.
    #[field(role = username, encoding = ascii)]
    pub username: String,

    /// SIP realm.
    #[field(role = other, encoding = ascii)]
    pub realm: String,

    /// Request method.
    #[field(role = other, encoding = ascii)]
    pub method: String,

    /// URI prefix.
    #[field(role = other, encoding = ascii)]
    pub uri_prefix: String,

    /// URI resource.
    #[field(role = salt, encoding = ascii)]
    pub uri_resource: String,

    /// URI suffix.
    #[field(role = other, encoding = ascii)]
    pub uri_suffix: String,

    /// Server nonce.
    #[field(role = other, encoding = ascii)]
    pub nonce: String,

    /// Client nonce.
    #[field(role = other, encoding = ascii)]
    pub nonce_client: String,

    /// Nonce count.
    #[field(role = other, encoding = ascii)]
    pub nonce_count: String,

    /// Quality of protection.
    #[field(role = other, encoding = ascii)]
    pub qop: String,

    /// Authentication directive.
    #[field(role = other, encoding = ascii)]
    pub directive: String,

    /// Sixteen-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 16],
}

impl Parse for SipDigest {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$sip$*", 0)?;
        let fields = parse::split_fields(rest, '*', 14)?;
        let text = |index: usize| fields[index].0.to_owned();
        Ok(Self {
            unused1: text(0),
            unused2: text(1),
            username: text(2),
            realm: text(3),
            method: text(4),
            uri_prefix: text(5),
            uri_resource: text(6),
            uri_suffix: text(7),
            nonce: text(8),
            nonce_client: text(9),
            nonce_count: text(10),
            qop: text(11),
            directive: text(12),
            digest: parse::decode_hex_field::<16>(fields[13].0, fields[13].1, "digest")?,
        })
    }
}

impl Render for SipDigest {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$sip$*{}*{}*{}*{}*{}*{}*{}*{}*{}*{}*{}*{}*{}*{}",
            self.unused1,
            self.unused2,
            self.username,
            self.realm,
            self.method,
            self.uri_prefix,
            self.uri_resource,
            self.uri_suffix,
            self.nonce,
            self.nonce_client,
            self.nonce_count,
            self.qop,
            self.directive,
            crate::format::hex(self.digest)
        )
    }
}
