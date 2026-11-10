//! Artifact extraction into the same hash type instances used by parsing.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::HashValue;

/// Hashes produced by one extractor.
pub type Extracted = Vec<Box<dyn HashValue>>;

/// Random-access byte source used by extractors.
pub trait ReadAt: Send + Sync {
    /// Total number of bytes available.
    fn len(&self) -> u64;

    /// Returns whether the source has no bytes.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Reads up to `out.len()` bytes starting at `offset`.
    ///
    /// A short read means the source ended. Reading at or past the end returns
    /// zero bytes.
    fn read_at(&self, offset: u64, out: &mut [u8]) -> io::Result<usize>;

    /// Reads exactly `out.len()` bytes starting at `offset`.
    fn read_exact_at(&self, mut offset: u64, mut out: &mut [u8]) -> io::Result<()> {
        while !out.is_empty() {
            match self.read_at(offset, out)? {
                0 => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "artifact ended before the requested range",
                    ));
                }
                read => {
                    offset += read as u64;
                    out = &mut out[read..];
                }
            }
        }
        Ok(())
    }

    /// Reads the whole source into memory.
    fn read_all(&self) -> io::Result<Vec<u8>> {
        let len = usize::try_from(self.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "artifact is too large"))?;
        let mut data = vec![0; len];
        self.read_exact_at(0, &mut data)?;
        Ok(data)
    }
}

/// In-memory artifact source.
#[derive(Clone, Debug)]
pub struct MemorySource {
    data: Arc<[u8]>,
}

impl MemorySource {
    /// Creates a source from owned bytes.
    #[must_use]
    pub fn new(data: Vec<u8>) -> Self {
        Self { data: data.into() }
    }
}

impl From<Vec<u8>> for MemorySource {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

impl ReadAt for MemorySource {
    fn len(&self) -> u64 {
        self.data.len() as u64
    }

    fn read_at(&self, offset: u64, out: &mut [u8]) -> io::Result<usize> {
        let offset = usize::try_from(offset).unwrap_or(usize::MAX);
        let Some(rest) = self.data.get(offset..) else {
            return Ok(0);
        };
        let read = rest.len().min(out.len());
        out[..read].copy_from_slice(&rest[..read]);
        Ok(read)
    }
}

/// File-backed artifact source with positioned reads.
pub struct FileSource {
    file: Mutex<File>,
    len: u64,
}

impl FileSource {
    /// Opens a file as a random-access source.
    pub fn open(path: &Path) -> io::Result<Self> {
        let file = File::open(path)?;
        let len = file.metadata()?.len();
        Ok(Self {
            file: Mutex::new(file),
            len,
        })
    }
}

impl ReadAt for FileSource {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, offset: u64, out: &mut [u8]) -> io::Result<usize> {
        if offset >= self.len {
            return Ok(0);
        }
        let mut file = self
            .file
            .lock()
            .map_err(|_| io::Error::other("artifact file lock is poisoned"))?;
        file.seek(SeekFrom::Start(offset))?;
        file.read(out)
    }
}

/// Role of a member inside a logical artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemberRole {
    /// Main input, such as a key file or a disk image.
    Primary,
    /// Named companion, such as `SAM`, `SYSTEM`, or `login-data`.
    Named(String),
}

/// One byte source belonging to an artifact.
pub struct ArtifactMember {
    /// Role that identifies this member.
    pub role: MemberRole,
    /// Byte source for the member.
    pub source: Box<dyn ReadAt>,
}

/// Logical input presented to extractors.
pub struct Artifact {
    label: String,
    members: Vec<ArtifactMember>,
}

impl Artifact {
    /// Creates an artifact with one primary member.
    #[must_use]
    pub fn new(label: impl Into<String>, source: impl ReadAt + 'static) -> Self {
        Self {
            label: label.into(),
            members: vec![ArtifactMember {
                role: MemberRole::Primary,
                source: Box::new(source),
            }],
        }
    }

    /// Creates an artifact from an in-memory byte string.
    #[must_use]
    pub fn from_bytes(label: impl Into<String>, data: Vec<u8>) -> Self {
        Self::new(label, MemorySource::from(data))
    }

    /// Opens a file as an artifact.
    pub fn from_file(path: &Path) -> io::Result<Self> {
        let mut artifact = Self::new(path.display().to_string(), FileSource::open(path)?);
        for (extension, role) in [("salt", "salt"), ("keyfile", "keyfile"), ("key", "keyfile")] {
            let companion = path.with_extension(extension);
            if companion.is_file() {
                artifact.members.push(ArtifactMember {
                    role: MemberRole::Named(role.to_owned()),
                    source: Box::new(FileSource::open(&companion)?),
                });
            }
        }
        Ok(artifact)
    }

    /// Adds a named companion member.
    #[must_use]
    pub fn with_member(mut self, name: impl Into<String>, source: impl ReadAt + 'static) -> Self {
        self.members.push(ArtifactMember {
            role: MemberRole::Named(name.into()),
            source: Box::new(source),
        });
        self
    }

    /// Human-readable artifact label.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Primary member.
    #[must_use]
    pub fn primary(&self) -> &dyn ReadAt {
        &*self.members[0].source
    }

    /// Looks up a named companion member.
    #[must_use]
    pub fn member(&self, name: &str) -> Option<&dyn ReadAt> {
        self.members.iter().find_map(|member| match &member.role {
            MemberRole::Named(role) if role == name => Some(&*member.source),
            _ => None,
        })
    }

    /// All members in declaration order.
    #[must_use]
    pub fn members(&self) -> &[ArtifactMember] {
        &self.members
    }
}

/// Result of asking an extractor whether it recognizes an artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Probe {
    /// This is not the extractor's format.
    No,
    /// The format is possible but has no reliable signature.
    Maybe(String),
    /// The extractor is confident that it recognizes the artifact.
    Yes(String),
}

impl Probe {
    /// Builds a `Maybe` probe with a reason.
    #[must_use]
    pub fn maybe(reason: impl Into<String>) -> Self {
        Self::Maybe(reason.into())
    }

    /// Builds a `Yes` probe with evidence.
    #[must_use]
    pub fn yes(evidence: impl Into<String>) -> Self {
        Self::Yes(evidence.into())
    }

    /// Returns the evidence or reason for a non-negative probe.
    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::No => None,
            Self::Maybe(reason) | Self::Yes(reason) => Some(reason),
        }
    }
}

/// A failure while extracting an artifact.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExtractError {
    /// The artifact is not in a shape this extractor understands.
    #[error("{0}")]
    Unsupported(String),
    /// The artifact is in the expected shape but is malformed.
    #[error("{0}")]
    Invalid(String),
}

/// One extractor for a hash type.
pub trait Extractor: Sync {
    /// Hash type slug this extractor produces.
    fn slug(&self) -> &'static str;

    /// Whether this extractor can return `Probe::Yes` for a valid artifact.
    ///
    /// Extractors that can only produce `Probe::Maybe` override this to return
    /// `false`.
    fn exact(&self) -> bool {
        true
    }

    /// Reports whether this extractor recognizes an artifact.
    fn probe(&self, artifact: &Artifact) -> Probe;

    /// Extracts every matching hash from an artifact.
    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError>;
}

/// Candidate extractor with the reason it matched.
pub struct Candidate {
    /// Registered extractor.
    pub extractor: &'static dyn Extractor,
    /// Probe evidence or reason.
    pub reason: String,
}

/// Outcome of probing every registered extractor.
pub enum Selection {
    /// Exactly one extractor is confident.
    Unique(&'static dyn Extractor),
    /// Several extractors are confident.
    Ambiguous(Vec<Candidate>),
    /// No extractor is confident, but some consider the artifact possible.
    Unconfirmed(Vec<Candidate>),
    /// No extractor recognized the artifact.
    None,
}

/// Probes extractors and applies the auto-selection policy.
///
/// `Unique` requires exactly one `Probe::Yes`. `Probe::Maybe` never selects an
/// extractor automatically.
#[must_use]
pub fn select(extractors: &[&'static dyn Extractor], artifact: &Artifact) -> Selection {
    let mut confident = Vec::new();
    let mut possible = Vec::new();

    for extractor in extractors {
        match extractor.probe(artifact) {
            Probe::No => {}
            Probe::Maybe(reason) => possible.push(Candidate {
                extractor: *extractor,
                reason,
            }),
            Probe::Yes(reason) => confident.push(Candidate {
                extractor: *extractor,
                reason,
            }),
        }
    }

    match confident.len() {
        1 => Selection::Unique(confident[0].extractor),
        0 if possible.is_empty() => Selection::None,
        0 => Selection::Unconfirmed(possible),
        _ => Selection::Ambiguous(confident),
    }
}

mod adxcrypt;
mod aix;
mod ansible;
mod bisq;
mod bitshares;
mod bks;
mod blockchain;
mod cardano;
mod cloudkeychain;
mod dashlane;
mod dmg;
mod ecryptfs;
mod electrum;
mod encfs;
mod enpass;
mod ethereum;
mod exodus;
mod fernet;
mod filezilla;
mod geli;
mod gpg;
mod hashdump;
mod hashlist;
mod iwork;
mod jwt;
mod known_hosts;
mod kwallet;
mod ldap;
mod lotus;
mod metamask;
mod monero;
mod multibit;
mod odf;
mod onepassword_agile;
mod openbsd_softraid;
mod pgpdisk;
mod pgpsda;
mod pgpwde;
mod pwsafe;
mod racf;
mod shadow;
mod sql;
mod vdi;
mod vmx;
mod winzip;

mod armory;
mod bitcoin_wallet;
mod bitcoin_wif;
mod bitshares_wallet;
mod bitwarden;
mod blockchain_second;
mod clipperz;
mod cryptosafe;
mod dogechain;
mod jks_private_key;
mod keepass;
mod keepass4;
mod keplr;
mod keyring;
mod krb5asrep23;
mod krb5asrep_aes;
mod krb5tgs23;
mod lastpass;
mod lpcli;
mod mozilla_key3;
mod mozilla_key4;
mod multibit_wallet;
mod office;
mod office2016_sheetprotection;
mod oldoffice;
mod onepassword_cloud;
mod onepassword_mobile;
mod openssl_enc;
mod pdf;
mod pem_private_key;
mod pfx;
mod pkzip;
mod pst;
mod putty;
mod pwsafe_v2;
mod rar3hp;
mod rar3p;
mod rar5;
mod sappse;
mod securezip;
mod sevenzip;
mod sshng;
mod stellar;
mod terra;
mod tezos;
mod wpa_pmkid;
mod wpa_pmkid_legacy;
mod xca;

mod android_backup;
mod android_fde;
mod android_fde_samsung;
mod apfs;
mod apple_dmg;
mod apple_keychain;
mod apple_secure_notes;
mod bitlocker;
mod chap;
mod dcc2;
mod diskcryptor;
mod dpapi;
mod eigrp;
mod filevault2;
mod flask_session;
mod fscrypt;
mod hsrp;
mod iphone_passcode;
mod iscsi_chap;
mod itunes_backup;
mod krb4;
mod krb5pa17;
mod krb5pa18;
mod krb5pa23;
mod krb5tgs17;
mod krb5tgs18;
mod luks_v1;
mod luks_v2;
mod macos_pbkdf2_sha512;
mod macos_sha1;
mod macos_sha512;
mod mschapv2_naive;
mod netntlmv1;
mod netntlmv2;
mod ntlm;
mod ospf_md5;
mod racf_kdfaes_passphrase;
mod radius;
mod signal;
mod sip_digest;
mod snmpv3;
mod sntp_ms;
mod sqlcipher;
mod tacacs_plus;
mod tcp_md5;
mod telegram;
mod truecrypt;
mod veeam;
mod veracrypt;
mod vmware_vmx;
mod windows_hello;

mod ike_john;
mod ike_psk_md5;
mod ike_psk_sha1;
mod krb5db17;
mod krb5db18;
mod krb5db_old;
mod pem;

pub static EXTRACTORS: &[&dyn Extractor] = &[
    &adxcrypt::AdxcryptExtractor,
    &aix::AixSmd5Extractor,
    &aix::AixSsha1Extractor,
    &aix::AixSsha256Extractor,
    &aix::AixSsha512Extractor,
    &ansible::AnsibleVaultExtractor,
    &bitshares::BitsharesExtractor,
    &bks::BksExtractor,
    &bisq::BisqExtractor,
    &blockchain::BlockchainExtractor,
    &cardano::CardanoExtractor,
    &cloudkeychain::CloudkeychainExtractor,
    &dashlane::DashlaneExtractor,
    &dmg::DmgExtractor,
    &ecryptfs::EcryptfsExtractor,
    &electrum::ElectrumExtractor,
    &encfs::EncfsExtractor,
    &ethereum::EthereumPbkdf2Extractor,
    &ethereum::EthereumPresaleExtractor,
    &ethereum::EthereumScryptExtractor,
    &enpass::EnpassExtractor,
    &exodus::ExodusExtractor,
    &fernet::FernetExtractor,
    &filezilla::FileZillaServerExtractor,
    &geli::GeliExtractor,
    &gpg::GpgExtractor,
    &iwork::IworkExtractor,
    &jwt::JwtExtractor,
    &hashdump::As400DesExtractor,
    &hashdump::As400Ssha1Extractor,
    &hashdump::LotusNotesExtractor,
    &hashdump::OpenvmsExtractor,
    &hashdump::Oracle11Extractor,
    &hashdump::Oracle12cExtractor,
    &hashdump::OracleOtmExtractor,
    &hashdump::RacfKdfaesExtractor,
    &hashdump::RacfPassphraseExtractor,
    &hashdump::SybasePropExtractor,
    &hashlist::Blake2b256Extractor,
    &hashlist::Blake2b512Extractor,
    &hashlist::Blake2s256Extractor,
    &hashlist::EdonR256Extractor,
    &hashlist::EdonR512Extractor,
    &hashlist::FugueExtractor,
    &hashlist::GroestlExtractor,
    &hashlist::HamsiExtractor,
    &hashlist::JhExtractor,
    &hashlist::LuffaExtractor,
    &hashlist::ShabalExtractor,
    &hashlist::Shavite3Extractor,
    &hashlist::SimdExtractor,
    &hashlist::GostExtractor,
    &hashlist::Has160Extractor,
    &hashlist::Mdc2Extractor,
    &hashlist::Md6Extractor,
    &hashlist::PanamaExtractor,
    &hashlist::RadioGatunExtractor,
    &hashlist::KeccakExtractor,
    &hashlist::LmExtractor,
    &hashlist::Md2Extractor,
    &hashlist::Md4Extractor,
    &hashlist::Md5Extractor,
    &ntlm::NtlmExtractor,
    &hashlist::RipemdExtractor,
    &hashlist::Sha0Extractor,
    &hashlist::Sha1Extractor,
    &hashlist::Sha224Extractor,
    &hashlist::Sha3Extractor,
    &hashlist::Sha256Extractor,
    &hashlist::Sha384Extractor,
    &hashlist::Sha512Extractor,
    &hashlist::Sm3Extractor,
    &hashlist::Skein512Extractor,
    &hashlist::SnefruExtractor,
    &hashlist::StreebogExtractor,
    &hashlist::TigerExtractor,
    &hashlist::WhirlpoolExtractor,
    &known_hosts::KnownHostsExtractor,
    &kwallet::KwalletExtractor,
    &lotus::Lotus5Extractor,
    &ldap::LdapSha1Extractor,
    &ldap::LdapSsha1Extractor,
    &ldap::LdapSsha256Extractor,
    &ldap::LdapSsha512Extractor,
    &vdi::VdiExtractor,
    &vdi::VirtualboxExtractor,
    &vmx::VmxExtractor,
    &winzip::WinZipExtractor,
    &monero::MoneroExtractor,
    &metamask::MetamaskExtractor,
    &metamask::MetamaskMobileExtractor,
    &multibit::MultibitHdExtractor,
    &multibit::MultibitKeyExtractor,
    &odf::OdfExtractor,
    &onepassword_agile::AgileKeychainExtractor,
    &onepassword_agile::OnepasswordAgileExtractor,
    &openbsd_softraid::OpenbsdSoftraidExtractor,
    &pgpdisk::PgpdiskExtractor,
    &pgpsda::PgpsdaExtractor,
    &pgpwde::PgpwdeExtractor,
    &pwsafe::PwsafeExtractor,
    &pwsafe::PwsafeV3Extractor,
    &racf::RacfExtractor,
    &shadow::Apr1Extractor,
    &shadow::BcryptExtractor,
    &shadow::BsdiCryptExtractor,
    &shadow::DesCryptExtractor,
    &shadow::Md5CryptExtractor,
    &shadow::Sha1cryptExtractor,
    &shadow::Sha256CryptExtractor,
    &shadow::Sha512CryptExtractor,
    &shadow::SunMd5Extractor,
    &shadow::YescryptExtractor,
    &sql::Mssql2000Extractor,
    &sql::Mssql2005Extractor,
    &sql::Mssql2012Extractor,
    &sql::Mssql2025Extractor,
    &sql::Mysql323Extractor,
    &sql::MysqlAExtractor,
    &sql::MysqlSha1Extractor,
    &sql::OracleHExtractor,
    &sql::OracleTExtractor,
    &sql::PostgresScramSha256Extractor,
    &pkzip::PkzipExtractor,
    &securezip::SecurezipExtractor,
    &rar3p::Rar3pExtractor,
    &rar3hp::Rar3hpExtractor,
    &office::OfficeExtractor,
    &office2016_sheetprotection::Office2016SheetprotectionExtractor,
    &oldoffice::OldOfficeExtractor,
    &rar5::Rar5Extractor,
    &sevenzip::SevenZipExtractor,
    &pdf::PdfExtractor,
    &pst::PstExtractor,
    &sappse::SappseExtractor,
    &openssl_enc::OpensslEncExtractor,
    &pfx::Pkcs12Extractor,
    &pfx::PfxJohnExtractor,
    &pem_private_key::PemPrivateKeyExtractor,
    &jks_private_key::JksPrivateKeyExtractor,
    &sshng::SshngExtractor,
    &putty::PuttyExtractor,
    &clipperz::ClipperzExtractor,
    &keepass::KeepassExtractor,
    &keepass4::Keepass4Extractor,
    &pwsafe_v2::PwsafeV2Extractor,
    &xca::XcaExtractor,
    &bitwarden::BitwardenExtractor,
    &lastpass::LastpassExtractor,
    &lpcli::LpcliExtractor,
    &onepassword_cloud::OnepasswordCloudExtractor,
    &onepassword_mobile::OnepasswordMobileExtractor,
    &armory::ArmoryExtractor,
    &cryptosafe::CryptosafeExtractor,
    &keyring::KeyringExtractor,
    &mozilla_key3::MozillaKey3Extractor,
    &mozilla_key4::MozillaKey4Extractor,
    &blockchain_second::BlockchainSecondExtractor,
    &dogechain::DogechainExtractor,
    &tezos::TezosExtractor,
    &keplr::KeplrExtractor,
    &stellar::StellarExtractor,
    &terra::TerraExtractor,
    &bitcoin_wif::BitcoinWifExtractor,
    &bitcoin_wallet::BitcoinWalletExtractor,
    &multibit_wallet::MultibitWalletExtractor,
    &bitshares_wallet::BitsharesWalletExtractor,
    &krb5asrep23::Krb5AsRep23Extractor,
    &krb5asrep_aes::Krb5AsrepAesExtractor,
    &krb5tgs23::Krb5Tgs23Extractor,
    &wpa_pmkid::WpaPmkidExtractor,
    &wpa_pmkid_legacy::WpaPmkidLegacyExtractor,
    &bitlocker::BitlockerExtractor,
    &dcc2::Dcc2Extractor,
    &dpapi::DpapiExtractor,
    &veeam::VeeamExtractor,
    &windows_hello::WindowsHelloExtractor,
    &apple_keychain::AppleKeychainExtractor,
    &apple_secure_notes::AppleSecureNotesExtractor,
    &macos_pbkdf2_sha512::MacosPbkdf2Sha512Extractor,
    &macos_sha1::MacosSha1Extractor,
    &macos_sha512::MacosSha512Extractor,
    &iphone_passcode::IphonePasscodeExtractor,
    &itunes_backup::ItunesBackupExtractor,
    &apple_dmg::AppleDmgExtractor,
    &android_backup::AndroidBackupExtractor,
    &android_fde::AndroidFdeExtractor,
    &luks_v1::LuksV1Extractor,
    &luks_v2::LuksV2Extractor,
    &truecrypt::TrueCryptExtractor,
    &veracrypt::VeraCryptExtractor,
    &diskcryptor::DiskcryptorExtractor,
    &filevault2::FileVault2Extractor,
    &apfs::ApfsExtractor,
    &android_fde_samsung::AndroidFdeSamsungExtractor,
    &fscrypt::FscryptExtractor,
    &vmware_vmx::VmwareVmxExtractor,
    &signal::SignalExtractor,
    &telegram::TelegramExtractor,
    &sqlcipher::SqlcipherExtractor,
    &flask_session::FlaskSessionExtractor,
    &racf_kdfaes_passphrase::RacfKdfaesPassphraseExtractor,
    &krb5tgs17::Krb5Tgs17Extractor,
    &krb5tgs18::Krb5Tgs18Extractor,
    &krb5pa23::Krb5Pa23Extractor,
    &krb5pa17::Krb5Pa17Extractor,
    &krb5pa18::Krb5Pa18Extractor,
    &chap::ChapExtractor,
    &krb4::Krb4Extractor,
    &mschapv2_naive::Mschapv2NaiveExtractor,
    &netntlmv1::NetNtlmV1Extractor,
    &netntlmv2::NetNtlmV2Extractor,
    &iscsi_chap::IscsiChapExtractor,
    &snmpv3::Snmpv3Extractor,
    &radius::RadiusExtractor,
    &tacacs_plus::TacacsPlusExtractor,
    &sip_digest::SipDigestExtractor,
    &ospf_md5::OspfMd5Extractor,
    &tcp_md5::TcpMd5Extractor,
    &hsrp::HsrpExtractor,
    &eigrp::EigrpExtractor,
    &sntp_ms::SntpMsExtractor,
    &pem::PemExtractor,
    &krb5db17::Krb5Db17Extractor,
    &krb5db18::Krb5Db18Extractor,
    &krb5db_old::Krb5DbOldExtractor,
    &ike_psk_md5::IkePskMd5Extractor,
    &ike_psk_sha1::IkePskSha1Extractor,
    &ike_john::IkeJohnExtractor,
];

/// Returns the extractor registered for a slug.
#[must_use]
pub fn by_slug(slug: &str) -> Option<&'static dyn Extractor> {
    EXTRACTORS
        .iter()
        .copied()
        .find(|extractor| extractor.slug() == slug)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fake {
        slug: &'static str,
        probe: fn() -> Probe,
    }

    impl Extractor for Fake {
        fn slug(&self) -> &'static str {
            self.slug
        }

        fn probe(&self, _: &Artifact) -> Probe {
            (self.probe)()
        }

        fn extract(&self, _: &Artifact) -> Result<Extracted, ExtractError> {
            Err(ExtractError::Unsupported("fake extractor".to_owned()))
        }
    }

    static YES_A: Fake = Fake {
        slug: "yes-a",
        probe: || Probe::yes("signature A"),
    };
    static YES_B: Fake = Fake {
        slug: "yes-b",
        probe: || Probe::yes("signature B"),
    };
    static MAYBE: Fake = Fake {
        slug: "maybe",
        probe: || Probe::maybe("no signature"),
    };
    static NO: Fake = Fake {
        slug: "no",
        probe: || Probe::No,
    };

    fn artifact() -> Artifact {
        Artifact::from_bytes("test", (0..=9).collect::<Vec<u8>>())
    }

    #[test]
    fn memory_source_reads_ranges_and_stops_at_the_end() {
        let source = MemorySource::from((0..=9).collect::<Vec<u8>>());
        let mut out = [0xff; 4];

        assert_eq!(source.len(), 10);
        assert_eq!(source.read_at(3, &mut out).unwrap(), 4);
        assert_eq!(out, [3, 4, 5, 6]);

        out[2..].fill(0xff);
        assert_eq!(source.read_at(8, &mut out).unwrap(), 2);
        assert_eq!(out, [8, 9, 0xff, 0xff]);

        assert_eq!(source.read_at(10, &mut out).unwrap(), 0);
        assert_eq!(source.read_at(u64::MAX, &mut out).unwrap(), 0);
    }

    #[test]
    fn read_exact_at_rejects_short_sources() {
        let source = MemorySource::from(vec![1, 2, 3]);
        let mut out = [0; 3];
        assert!(source.read_exact_at(0, &mut out).is_ok());

        let error = source.read_exact_at(1, &mut out).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn artifact_exposes_label_members_and_companions() {
        let artifact = Artifact::from_bytes("main.bin", vec![1, 2, 3])
            .with_member("SYSTEM", MemorySource::from(vec![4, 5]));

        assert_eq!(artifact.label(), "main.bin");
        assert_eq!(artifact.primary().read_all().unwrap(), [1, 2, 3]);
        assert_eq!(
            artifact.member("SYSTEM").unwrap().read_all().unwrap(),
            [4, 5]
        );
        assert!(artifact.member("SAM").is_none());
        assert_eq!(artifact.members().len(), 2);
    }

    #[test]
    fn select_requires_exactly_one_confident_probe() {
        let artifact = artifact();

        assert!(matches!(
            select(&[&NO, &MAYBE], &artifact),
            Selection::Unconfirmed(candidates) if candidates.len() == 1
        ));
        assert!(matches!(select(&[&NO], &artifact), Selection::None));
        assert!(matches!(
            select(&[&MAYBE, &YES_A], &artifact),
            Selection::Unique(extractor) if extractor.slug() == "yes-a"
        ));
        assert!(matches!(
            select(&[&YES_A, &YES_B], &artifact),
            Selection::Ambiguous(candidates) if candidates.len() == 2
        ));
        assert!(matches!(
            select(&[&NO, &MAYBE], &artifact),
            Selection::Unconfirmed(candidates)
                if candidates[0].reason == "no signature"
        ));
    }

    #[test]
    fn selection_does_not_call_extract() {
        struct Counting;
        static CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

        impl Extractor for Counting {
            fn slug(&self) -> &'static str {
                "counting"
            }

            fn probe(&self, _: &Artifact) -> Probe {
                Probe::maybe("try me")
            }

            fn extract(&self, _: &Artifact) -> Result<Extracted, ExtractError> {
                CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(Vec::new())
            }
        }

        let _ = select(&[&Counting], &artifact());
        assert_eq!(CALLS.load(std::sync::atomic::Ordering::Relaxed), 0);
    }
}
