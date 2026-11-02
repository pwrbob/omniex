//! Core runtime types shared by `omniex`.
//!
//! This crate contains no CLI, no I/O, and no concrete hash implementations. It
//! defines the metadata and traits that hash types use, so the proc-macro crate
//! and the public `omniex` facade can share one data model.

pub mod format;

/// Static description of one struct member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Field {
    /// Rust field name, or the `rename` value.
    pub name: &'static str,
    /// Doc comment text.
    pub description: &'static str,
    /// The Rust type, as a string, for `--verbose` and JSON.
    pub ty: &'static str,
    /// Semantic role of the member.
    pub role: FieldRole,
    /// How to render the value.
    pub encoding: Encoding,
}

/// Semantic role of a hash-type field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FieldRole {
    /// Salt value.
    Salt,
    /// HMAC or other key value.
    Key,
    /// Digest value.
    Digest,
    /// Initialization vector.
    Iv,
    /// Ciphertext.
    Ciphertext,
    /// Iteration count.
    Iterations,
    /// User name.
    Username,
    /// Any other value.
    Other,
}

/// How a field value is encoded in output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Encoding {
    /// Format via `Debug`.
    Raw,
    /// Lowercase hexadecimal.
    Hex,
    /// Base64.
    Base64,
    /// Decimal.
    Decimal,
    /// ASCII.
    Ascii,
}

/// A hashcat or John mode.
///
/// John modes are named format labels only, for example `"bcrypt"` or
/// `"dynamic_0"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Mode {
    /// A hashcat mode number.
    Hashcat(u32),
    /// A John format label.
    John(&'static str),
}

/// One rendered member: metadata plus its current value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldValue {
    /// The field metadata.
    pub field: &'static Field,
    /// The rendered value.
    pub value: String,
}

/// Metadata shared by every concrete hash type.
///
/// This trait is metadata-only. Parsing, rendering, description, and mode
/// compatibility live in [`Parse`], [`Render`], [`Describe`], and
/// [`ModeCompat`].
///
/// It is not object-safe because it has associated constants. The CLI should
/// dispatch through the descriptor registry instead of `dyn HashType`.
pub trait HashType {
    /// Human-readable name.
    const NAME: &'static str;
    /// Stable machine-readable identifier.
    const SLUG: &'static str;
    /// Metadata for every field.
    const FIELDS: &'static [Field];
}

/// The target tool for rendering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tool {
    /// Hashcat.
    Hashcat,
    /// John the Ripper.
    John,
}

/// An official hashcat release. Ordered for feature checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReleaseVersion {
    /// Major version.
    pub major: u16,
    /// Minor version.
    pub minor: u16,
    /// Patch version.
    pub patch: u16,
}

impl ReleaseVersion {
    /// Creates a release version.
    #[must_use]
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
}

/// A pinned hashcat master snapshot. Not ordered: tests pin an exact commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MasterSnapshot {
    /// Full commit hash.
    pub commit: &'static str,
    /// ISO 8601 commit date, for display only.
    pub date: &'static str,
}

/// A hashcat build `omniex` can target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashcatVersion {
    /// Official release. Mismatches are gating.
    Release(ReleaseVersion),
    /// Master snapshot. Mismatches are informational only.
    Master(MasterSnapshot),
}

impl HashcatVersion {
    /// The first hashcat release supported by `omniex`.
    pub const FIRST_SUPPORTED_RELEASE: Self = Self::Release(ReleaseVersion::new(8, 0, 0));

    /// Newest official release known to `omniex`. This is the default target.
    pub const NEWEST_RELEASE: Self = Self::Release(ReleaseVersion::new(8, 0, 0));

    /// Returns `true` for an official release.
    #[must_use]
    pub const fn is_release(self) -> bool {
        matches!(self, Self::Release(_))
    }

    /// Returns the release version, or `None` for a master snapshot.
    #[must_use]
    pub const fn release(self) -> Option<ReleaseVersion> {
        match self {
            Self::Release(version) => Some(version),
            Self::Master(_) => None,
        }
    }
}

/// Options that affect rendering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RenderOptions {
    /// Target tool.
    pub tool: Tool,
    /// Hashcat version used when rendering for hashcat.
    pub hc_version: HashcatVersion,
}

impl Default for RenderOptions {
    fn default() -> Self {
        Self {
            tool: Tool::Hashcat,
            hc_version: HashcatVersion::NEWEST_RELEASE,
        }
    }
}

/// A rendering request that cannot be satisfied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RenderError {
    /// The value has no mode for the requested tool.
    #[error("{}", unsupported_tool(*.0))]
    UnsupportedTool(Tool),
    /// The requested hashcat release predates support.
    #[error(
        "hashcat {}.{}.{} is older than the first supported release",
        .0.major,
        .0.minor,
        .0.patch
    )]
    UnsupportedRelease(ReleaseVersion),
}

fn unsupported_tool(tool: Tool) -> &'static str {
    match tool {
        Tool::Hashcat => "no compatible hashcat mode for this value",
        Tool::John => "no compatible John format for this value",
    }
}

/// Serializes a hash type into the string consumed by hashcat or John.
///
/// Implemented manually per hash type. `render_value` performs the
/// serialization; callers should prefer `render`, which first verifies that the
/// value supports the requested tool and release.
pub trait Render: ModeCompat {
    /// Serialize without checking tool or version compatibility.
    fn render_value(&self, opts: &RenderOptions) -> String;

    /// Render the type using the given options.
    fn render(&self, opts: &RenderOptions) -> Result<String, RenderError> {
        if let Some(version) = opts.hc_version.release() {
            if let Some(first) = HashcatVersion::FIRST_SUPPORTED_RELEASE.release() {
                if version < first {
                    return Err(RenderError::UnsupportedRelease(version));
                }
            }
        }

        let supported = self.modes().iter().any(|mode| {
            matches!(
                (mode, opts.tool),
                (Mode::Hashcat(_), Tool::Hashcat) | (Mode::John(_), Tool::John)
            )
        });

        if !supported {
            return Err(RenderError::UnsupportedTool(opts.tool));
        }

        Ok(self.render_value(opts))
    }
}

/// Reports the current values of a hash type's fields.
pub trait Describe {
    /// Values for `--verbose` and JSON output.
    fn describe(&self) -> Vec<FieldValue>;
}

/// Reports the modes that work for the concrete field values.
pub trait ModeCompat {
    /// Modes that can attack this value.
    fn modes(&self) -> Vec<Mode>;
}

/// Object-safe bundle used by the descriptor registry.
pub trait HashValue: Render + Describe + ModeCompat {}

impl<T: Render + Describe + ModeCompat> HashValue for T {}

/// Parses one hash string into a concrete hash type.
pub trait Parse: Sized {
    /// Parses `input` using the target tool and version.
    fn parse(input: &str, opts: &ParseOptions) -> Result<Self, ParseError>;
}

/// Options that affect parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseOptions {
    /// Target tool.
    pub tool: Tool,
    /// Hashcat version used when parsing for hashcat.
    pub hc_version: HashcatVersion,
}

impl Default for ParseOptions {
    fn default() -> Self {
        Self {
            tool: Tool::Hashcat,
            hc_version: HashcatVersion::NEWEST_RELEASE,
        }
    }
}

/// A parse failure with a byte offset into the input.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{} (at byte {})", .message, .offset)]
pub struct ParseError {
    /// Machine-readable error category.
    pub kind: ParseErrorKind,
    /// Byte offset where the error was detected.
    pub offset: usize,
    /// Human-readable explanation.
    pub message: String,
}

/// Categories for parse failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ParseErrorKind {
    /// The input was empty.
    Empty,
    /// A field had the wrong length.
    InvalidLength,
    /// Invalid hexadecimal input.
    InvalidHex,
    /// Invalid base64 input.
    InvalidBase64,
    /// An unexpected character was found.
    InvalidCharacter,
    /// The mode is not supported by this hash type.
    Unsupported,
    /// Any other parse error.
    Other,
}

/// Parses a hash string into a boxed runtime value.
pub type ParseFn = fn(&str, &ParseOptions) -> Result<Box<dyn HashValue>, ParseError>;

/// Type-erased metadata and parser for one hash type.
pub struct HashTypeDescriptor {
    /// Human-readable name.
    pub name: &'static str,
    /// Stable machine-readable identifier.
    pub slug: &'static str,
    /// Metadata for every field.
    pub fields: &'static [Field],
    /// Every mode the type can ever support.
    pub all_modes: &'static [Mode],
    /// Parses a hash string into a boxed runtime value.
    pub parse: ParseFn,
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Example;

    impl HashType for Example {
        const NAME: &'static str = "Example";
        const SLUG: &'static str = "example";
        const FIELDS: &'static [Field] = &[];
    }

    impl Describe for Example {
        fn describe(&self) -> Vec<FieldValue> {
            Vec::new()
        }
    }

    impl ModeCompat for Example {
        fn modes(&self) -> Vec<Mode> {
            vec![Mode::Hashcat(0), Mode::John("raw-md5")]
        }
    }

    impl Render for Example {
        fn render_value(&self, _opts: &RenderOptions) -> String {
            "example".to_owned()
        }
    }

    impl Parse for Example {
        fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
            if input == "example" {
                Ok(Self)
            } else {
                Err(ParseError {
                    kind: ParseErrorKind::InvalidCharacter,
                    offset: 0,
                    message: "expected `example`".to_owned(),
                })
            }
        }
    }

    impl Example {
        const DESCRIPTOR: HashTypeDescriptor = HashTypeDescriptor {
            name: Self::NAME,
            slug: Self::SLUG,
            fields: Self::FIELDS,
            all_modes: &[Mode::Hashcat(0), Mode::John("raw-md5")],
            parse: |input, opts| Ok(Box::new(<Self as Parse>::parse(input, opts)?)),
        };
    }

    #[test]
    fn hash_type_is_metadata_only() {
        assert_eq!(Example::NAME, "Example");
        assert_eq!(Example::SLUG, "example");
        assert!(Example::FIELDS.is_empty());
    }

    #[test]
    fn hash_value_bundles_runtime_traits() {
        let value: Box<dyn HashValue> = Box::new(Example);

        assert_eq!(value.modes(), vec![Mode::Hashcat(0), Mode::John("raw-md5")]);
        assert!(value.describe().is_empty());
        assert_eq!(value.render(&RenderOptions::default()).unwrap(), "example");
    }

    #[test]
    fn descriptor_parses_to_a_hash_value() {
        let value = (Example::DESCRIPTOR.parse)("example", &ParseOptions::default())
            .expect("example parses");

        assert_eq!(value.render(&RenderOptions::default()).unwrap(), "example");
        assert_eq!(value.modes(), vec![Mode::Hashcat(0), Mode::John("raw-md5")]);
    }

    #[test]
    fn render_rejects_unsupported_releases() {
        let opts = RenderOptions {
            hc_version: HashcatVersion::Release(ReleaseVersion::new(7, 1, 2)),
            ..RenderOptions::default()
        };

        assert_eq!(
            Example.render(&opts),
            Err(RenderError::UnsupportedRelease(ReleaseVersion::new(
                7, 1, 2
            )))
        );
    }

    #[test]
    fn render_options_default_to_hashcat() {
        let opts = RenderOptions::default();

        assert_eq!(opts.tool, Tool::Hashcat);
        assert_eq!(opts.hc_version, HashcatVersion::NEWEST_RELEASE);
    }

    #[test]
    fn parse_options_default_to_hashcat() {
        let opts = ParseOptions::default();

        assert_eq!(opts.tool, Tool::Hashcat);
        assert_eq!(opts.hc_version, HashcatVersion::NEWEST_RELEASE);
    }

    #[test]
    fn initial_release_is_8_0_0() {
        assert_eq!(
            HashcatVersion::FIRST_SUPPORTED_RELEASE.release(),
            Some(ReleaseVersion::new(8, 0, 0))
        );
        assert_eq!(
            HashcatVersion::NEWEST_RELEASE.release(),
            Some(ReleaseVersion::new(8, 0, 0))
        );
        assert!(HashcatVersion::NEWEST_RELEASE.is_release());
    }

    #[test]
    fn release_versions_are_ordered() {
        assert!(ReleaseVersion::new(7, 1, 2) < ReleaseVersion::new(8, 0, 0));
        assert!(ReleaseVersion::new(8, 0, 0) < ReleaseVersion::new(8, 0, 1));
    }

    #[test]
    fn master_snapshots_are_not_releases() {
        let master = HashcatVersion::Master(MasterSnapshot {
            commit: "0123456789abcdef",
            date: "2026-10-29",
        });

        assert!(!master.is_release());
        assert_eq!(master.release(), None);
    }
}
