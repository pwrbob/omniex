//! Static registry of every concrete hash type.

use crate::types::{
    ArubaSha1, Blake2b512, DjangoSha1, Episerver, HmacMd5, HmacSha1, JuniperIve, JuniperScreenos,
    LdapSha1, LdapSsha1, MacosSha1, Md4, Md5, Md5Crypt, Mssql2000, Mssql2005, Mysql323, OracleSha1,
    PeoplesoftSha1, Phpass, SaltedBlake2b512, SaltedMd5, SaltedSha1, Sha1,
};
use crate::{HashTypeDescriptor, ParseError, ParseFn, ParseOptions};

/// Every hash type known to this build.
pub static REGISTRY: &[&HashTypeDescriptor] = &[
    &Md4::DESCRIPTOR,
    &Md5::DESCRIPTOR,
    &SaltedMd5::DESCRIPTOR,
    &HmacMd5::DESCRIPTOR,
    &Sha1::DESCRIPTOR,
    &SaltedSha1::DESCRIPTOR,
    &HmacSha1::DESCRIPTOR,
    &OracleSha1::DESCRIPTOR,
    &LdapSha1::DESCRIPTOR,
    &LdapSsha1::DESCRIPTOR,
    &MacosSha1::DESCRIPTOR,
    &DjangoSha1::DESCRIPTOR,
    &ArubaSha1::DESCRIPTOR,
    &Mssql2000::DESCRIPTOR,
    &Mssql2005::DESCRIPTOR,
    &PeoplesoftSha1::DESCRIPTOR,
    &Episerver::DESCRIPTOR,
    &Mysql323::DESCRIPTOR,
    &Phpass::DESCRIPTOR,
    &Md5Crypt::DESCRIPTOR,
    &JuniperIve::DESCRIPTOR,
    &JuniperScreenos::DESCRIPTOR,
    &Blake2b512::DESCRIPTOR,
    &SaltedBlake2b512::DESCRIPTOR,
];

/// Returns every registered descriptor.
#[must_use]
pub fn all() -> &'static [&'static HashTypeDescriptor] {
    REGISTRY
}

/// Looks up a descriptor by slug.
#[must_use]
pub fn by_slug(slug: &str) -> Option<&'static HashTypeDescriptor> {
    REGISTRY.iter().copied().find(|entry| entry.slug == slug)
}

/// Parses through a descriptor.
pub fn parse(
    descriptor: &HashTypeDescriptor,
    input: &str,
    opts: &ParseOptions,
) -> Result<Box<dyn crate::HashValue>, ParseError> {
    let parse: ParseFn = descriptor.parse;
    parse(input, opts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Mode;

    #[test]
    fn slugs_are_unique_and_valid() {
        let mut slugs = Vec::new();
        for descriptor in all() {
            assert!(
                !descriptor.slug.is_empty()
                    && descriptor.slug.bytes().all(|byte| byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || byte == b'-'),
                "invalid slug {}",
                descriptor.slug
            );
            assert!(
                !slugs.contains(&descriptor.slug),
                "duplicate slug {}",
                descriptor.slug
            );
            slugs.push(descriptor.slug);
        }
    }

    #[test]
    fn every_type_has_fields_and_modes() {
        for descriptor in all() {
            assert!(!descriptor.fields.is_empty(), "{}", descriptor.slug);
            assert!(!descriptor.all_modes.is_empty(), "{}", descriptor.slug);
            for field in descriptor.fields {
                assert!(!field.description.is_empty(), "{}", field.name);
                assert!(!field.ty.is_empty(), "{}", field.name);
            }
        }
    }

    #[test]
    fn reference_types_are_registered() {
        assert!(by_slug("md5").is_some());
        assert!(by_slug("salted-md5").is_some());
        assert!(by_slug("missing").is_none());
    }

    #[test]
    fn md5_declares_expected_metadata() {
        let descriptor = by_slug("md5").expect("md5 registered");
        assert_eq!(descriptor.name, "MD5");
        assert_eq!(
            descriptor.all_modes,
            &[Mode::Hashcat(0), Mode::Hashcat(70), Mode::John("Raw-MD5")]
        );
        assert_eq!(descriptor.fields[0].name, "digest");
        assert_eq!(descriptor.fields[0].ty, "[u8; 16]");
    }
}
