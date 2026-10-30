//! Static registry of every concrete hash type.

use crate::types::*;
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
    &Ntlm::DESCRIPTOR,
    &Dcc::DESCRIPTOR,
    &Sha224::DESCRIPTOR,
    &Sha256::DESCRIPTOR,
    &SaltedSha256::DESCRIPTOR,
    &HmacSha256::DESCRIPTOR,
    &HmailServer::DESCRIPTOR,
    &Sha512::DESCRIPTOR,
    &SaltedSha512::DESCRIPTOR,
    &HmacSha512::DESCRIPTOR,
    &LdapSsha256::DESCRIPTOR,
    &LdapSsha512::DESCRIPTOR,
    &EpiserverNet4::DESCRIPTOR,
    &DesCrypt::DESCRIPTOR,
    &Apr1::DESCRIPTOR,
    &MacosSha512::DESCRIPTOR,
    &Mssql2012::DESCRIPTOR,
    &Sha512Crypt::DESCRIPTOR,
    &Dcc2::DESCRIPTOR,
    &CiscoPix::DESCRIPTOR,
    &CiscoAsa::DESCRIPTOR,
    &Phps::DESCRIPTOR,
    &Lm::DESCRIPTOR,
    &OracleH::DESCRIPTOR,
    &Bcrypt::DESCRIPTOR,
    &SunMd5::DESCRIPTOR,
    &WpaPmkid::DESCRIPTOR,
    &MediaWikiB::DESCRIPTOR,
    &Md5TwoSalts::DESCRIPTOR,
    &IscsiChap::DESCRIPTOR,
    &HalfMd5::DESCRIPTOR,
    &IkePskMd5::DESCRIPTOR,
    &IkePskSha1::DESCRIPTOR,
    &NetNtlmV1::DESCRIPTOR,
    &NetNtlmV2::DESCRIPTOR,
    &CiscoIos4::DESCRIPTOR,
    &SamsungAndroid::DESCRIPTOR,
    &Ripemd160::DESCRIPTOR,
    &Whirlpool::DESCRIPTOR,
    &Gost::DESCRIPTOR,
    &Sha384::DESCRIPTOR,
    &SaltedSha384::DESCRIPTOR,
    &Sha384Utf16::DESCRIPTOR,
    &Sha3_224::DESCRIPTOR,
    &Sha3_256::DESCRIPTOR,
    &Sha3_384::DESCRIPTOR,
    &Sha3_512::DESCRIPTOR,
    &Keccak224::DESCRIPTOR,
    &Keccak256::DESCRIPTOR,
    &Keccak384::DESCRIPTOR,
    &Keccak512::DESCRIPTOR,
    &Md2::DESCRIPTOR,
    &Sha0::DESCRIPTOR,
    &Ripemd128::DESCRIPTOR,
    &Ripemd256::DESCRIPTOR,
    &Gost94CryptoPro::DESCRIPTOR,
    &Tiger::DESCRIPTOR,
    &Tiger128::DESCRIPTOR,
    &Tiger160::DESCRIPTOR,
    &Tiger2::DESCRIPTOR,
    &Tth::DESCRIPTOR,
    &Snefru128::DESCRIPTOR,
    &Snefru256::DESCRIPTOR,
    &Skein512_224::DESCRIPTOR,
    &Skein512_256::DESCRIPTOR,
    &Skein512_384::DESCRIPTOR,
    &Skein512_512::DESCRIPTOR,
    &Panama::DESCRIPTOR,
    &Mdc2::DESCRIPTOR,
    &Haval128_3::DESCRIPTOR,
    &Haval128_4::DESCRIPTOR,
    &Haval128_5::DESCRIPTOR,
    &Haval160_3::DESCRIPTOR,
    &Haval160_4::DESCRIPTOR,
    &Haval160_5::DESCRIPTOR,
    &Haval192_3::DESCRIPTOR,
    &Haval192_4::DESCRIPTOR,
    &Haval192_5::DESCRIPTOR,
    &Haval224_3::DESCRIPTOR,
    &Haval224_4::DESCRIPTOR,
    &Haval224_5::DESCRIPTOR,
    &Haval256_3::DESCRIPTOR,
    &Haval256_4::DESCRIPTOR,
    &Haval256_5::DESCRIPTOR,
    &Blake224::DESCRIPTOR,
    &Blake256::DESCRIPTOR,
    &Blake384::DESCRIPTOR,
    &Blake512::DESCRIPTOR,
    &Bmw224::DESCRIPTOR,
    &Bmw256::DESCRIPTOR,
    &Bmw384::DESCRIPTOR,
    &Bmw512::DESCRIPTOR,
    &CubeHash224::DESCRIPTOR,
    &CubeHash256::DESCRIPTOR,
    &CubeHash384::DESCRIPTOR,
    &CubeHash512::DESCRIPTOR,
    &Echo224::DESCRIPTOR,
    &Echo256::DESCRIPTOR,
    &Echo384::DESCRIPTOR,
    &Echo512::DESCRIPTOR,
    &Fugue224::DESCRIPTOR,
    &Fugue256::DESCRIPTOR,
    &Fugue384::DESCRIPTOR,
    &Fugue512::DESCRIPTOR,
    &Groestl224::DESCRIPTOR,
    &Groestl256::DESCRIPTOR,
    &Groestl384::DESCRIPTOR,
    &Groestl512::DESCRIPTOR,
    &Hamsi224::DESCRIPTOR,
    &Hamsi256::DESCRIPTOR,
    &Hamsi384::DESCRIPTOR,
    &Hamsi512::DESCRIPTOR,
    &Jh224::DESCRIPTOR,
    &Jh256::DESCRIPTOR,
    &Jh384::DESCRIPTOR,
    &Jh512::DESCRIPTOR,
    &Luffa224::DESCRIPTOR,
    &Luffa256::DESCRIPTOR,
    &Luffa384::DESCRIPTOR,
    &Luffa512::DESCRIPTOR,
    &Shabal224::DESCRIPTOR,
    &Shabal256::DESCRIPTOR,
    &Shabal384::DESCRIPTOR,
    &Shabal512::DESCRIPTOR,
    &Shavite3224::DESCRIPTOR,
    &Shavite3256::DESCRIPTOR,
    &Shavite3384::DESCRIPTOR,
    &Shavite3512::DESCRIPTOR,
    &Simd224::DESCRIPTOR,
    &Simd256::DESCRIPTOR,
    &Simd384::DESCRIPTOR,
    &Simd512::DESCRIPTOR,
    &Has160::DESCRIPTOR,
    &EdonR256::DESCRIPTOR,
    &EdonR512::DESCRIPTOR,
    &Md6_128::DESCRIPTOR,
    &Md6_512::DESCRIPTOR,
    &RadioGatun32::DESCRIPTOR,
    &RadioGatun64::DESCRIPTOR,
    &RipemdOriginal::DESCRIPTOR,
    &Whirlpool0::DESCRIPTOR,
    &WhirlpoolT::DESCRIPTOR,
    &Sha256Md5::DESCRIPTOR,
    &Md5Sha1Md5Sha1::DESCRIPTOR,
    &Sha256Double::DESCRIPTOR,
    &Sha1DoubleMd5::DESCRIPTOR,
    &Sha224Double::DESCRIPTOR,
    &Sha224Sha1::DESCRIPTOR,
    &NtlmDouble::DESCRIPTOR,
    &Sha256DoubleSalt::DESCRIPTOR,
    &Sha1Md5::DESCRIPTOR,
    &Md5Sha1Md5::DESCRIPTOR,
    &Sha256SandwichSalt::DESCRIPTOR,
    &Sha1NestedSalt::DESCRIPTOR,
    &Sha256SaltSha256::DESCRIPTOR,
    &Sha256NestedSalted::DESCRIPTOR,
    &Md5SaltSha1Salt::DESCRIPTOR,
    &Sha256SaltSha256Bin::DESCRIPTOR,
    &Md5Simpla::DESCRIPTOR,
    &Sha512DoubleSalt::DESCRIPTOR,
    &Sha512DoubleBinSalt::DESCRIPTOR,
    &WhirlpoolCubeCart::DESCRIPTOR,
    &Md5SandwichSalt::DESCRIPTOR,
    &Md5TwoNestedSalts::DESCRIPTOR,
    &Md5TripleTwoSalts::DESCRIPTOR,
    &Sha1TwoSalts::DESCRIPTOR,
    &AuthMeSha256::DESCRIPTOR,
    &NetWitnessSha256::DESCRIPTOR,
    &Sha1Utf16UsernameSalt::DESCRIPTOR,
    &AixSmd5::DESCRIPTOR,
    &AixSsha1::DESCRIPTOR,
    &AixSsha256::DESCRIPTOR,
    &AixSsha512::DESCRIPTOR,
    &Sha256Crypt::DESCRIPTOR,
    &CitrixNetScalerSha1::DESCRIPTOR,
    &Wbb3::DESCRIPTOR,
    &QnxMd5::DESCRIPTOR,
    &QnxSha256::DESCRIPTOR,
    &QnxSha512::DESCRIPTOR,
    &Pbkdf2HmacMd5::DESCRIPTOR,
    &Pbkdf2HmacSha1::DESCRIPTOR,
    &Pbkdf2HmacSha256::DESCRIPTOR,
    &Pbkdf2HmacSha512::DESCRIPTOR,
    &PasslibPbkdf2Sha512::DESCRIPTOR,
    &PasslibPbkdf2Sha256::DESCRIPTOR,
    &PasslibPbkdf2Sha1::DESCRIPTOR,
    &DjangoPbkdf2Sha256::DESCRIPTOR,
    &AtlassianPbkdf2Sha1::DESCRIPTOR,
    &Prestashop::DESCRIPTOR,
    &Sha1crypt::DESCRIPTOR,
    &Drupal7::DESCRIPTOR,
    &CiscoIos8::DESCRIPTOR,
    &MacosPbkdf2Sha512::DESCRIPTOR,
    &Pbkdf1Sha1::DESCRIPTOR,
    &Web2pyPbkdf2Sha512::DESCRIPTOR,
    &Crc32::DESCRIPTOR,
    &Crc32C::DESCRIPTOR,
    &MurmurHash::DESCRIPTOR,
    &MurmurHash3::DESCRIPTOR,
    &Crc64Jones::DESCRIPTOR,
    &JavaHashcode::DESCRIPTOR,
    &Siphash::DESCRIPTOR,
    &Streebog256::DESCRIPTOR,
    &Streebog512::DESCRIPTOR,
    &HmacRipemd160Pass::DESCRIPTOR,
    &HmacRipemd160Salt::DESCRIPTOR,
    &HmacStreebog256Pass::DESCRIPTOR,
    &HmacStreebog256Salt::DESCRIPTOR,
    &HmacStreebog512Pass::DESCRIPTOR,
    &HmacStreebog512Salt::DESCRIPTOR,
    &HmacBlake2sPass::DESCRIPTOR,
    &HmacRipemd320Pass::DESCRIPTOR,
    &HmacRipemd320Salt::DESCRIPTOR,
    &SaltedSha224::DESCRIPTOR,
    &UuidV3::DESCRIPTOR,
    &UuidV5::DESCRIPTOR,
    &ModxEvolution::DESCRIPTOR,
    &CiscoIseSha256::DESCRIPTOR,
    &Fortigate256::DESCRIPTOR,
    &Qnx7Sha512::DESCRIPTOR,
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
            &[
                Mode::Hashcat(0),
                Mode::Hashcat(70),
                Mode::Hashcat(2600),
                Mode::Hashcat(3500),
                Mode::Hashcat(4300),
                Mode::Hashcat(4400),
                Mode::John("Raw-MD5"),
            ]
        );
        assert_eq!(descriptor.fields[0].name, "digest");
        assert_eq!(descriptor.fields[0].ty, "[u8; 16]");
    }
}
