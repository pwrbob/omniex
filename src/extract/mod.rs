//! Artifact extraction into the same hash type instances used by parsing.

use std::fmt;
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
        Ok(Self::new(
            path.display().to_string(),
            FileSource::open(path)?,
        ))
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtractError {
    /// The artifact is not in a shape this extractor understands.
    Unsupported(String),
    /// The artifact is in the expected shape but is malformed.
    Invalid(String),
}

impl fmt::Display for ExtractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(message) | Self::Invalid(message) => f.write_str(message),
        }
    }
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

mod ansible;
mod bks;
mod blockchain;
mod dashlane;
mod dmg;
mod ecryptfs;
mod electrum;
mod encfs;
mod enpass;
mod ethereum;
mod fernet;
mod filezilla;
mod geli;
mod gpg;
mod iwork;
mod jwt;
mod known_hosts;
mod kwallet;
mod monero;
mod odf;
mod onepassword_agile;
mod openbsd_softraid;
mod pgpsda;
mod pwsafe;
mod winzip;

pub static EXTRACTORS: &[&dyn Extractor] = &[
    &ansible::AnsibleVaultExtractor,
    &bks::BksExtractor,
    &blockchain::BlockchainExtractor,
    &dashlane::DashlaneExtractor,
    &dmg::DmgExtractor,
    &ecryptfs::EcryptfsExtractor,
    &electrum::ElectrumExtractor,
    &encfs::EncfsExtractor,
    &ethereum::EthereumPbkdf2Extractor,
    &ethereum::EthereumPresaleExtractor,
    &ethereum::EthereumScryptExtractor,
    &enpass::EnpassExtractor,
    &fernet::FernetExtractor,
    &filezilla::FileZillaServerExtractor,
    &geli::GeliExtractor,
    &gpg::GpgExtractor,
    &iwork::IworkExtractor,
    &jwt::JwtExtractor,
    &known_hosts::KnownHostsExtractor,
    &kwallet::KwalletExtractor,
    &winzip::WinZipExtractor,
    &monero::MoneroExtractor,
    &odf::OdfExtractor,
    &onepassword_agile::AgileKeychainExtractor,
    &onepassword_agile::OnepasswordAgileExtractor,
    &openbsd_softraid::OpenbsdSoftraidExtractor,
    &pgpsda::PgpsdaExtractor,
    &pwsafe::PwsafeExtractor,
    &pwsafe::PwsafeV3Extractor,
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
