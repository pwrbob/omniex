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

/// Fixed algorithm families. Grows as modes are added.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Family {
    /// MD5 family.
    Md5,
    /// SHA-1 family.
    Sha1,
    /// SHA-2 family.
    Sha2,
    /// SHA-3 family.
    Sha3,
    /// BLAKE2 family.
    Blake2,
    /// RIPEMD family.
    Ripemd,
    /// Whirlpool family.
    Whirlpool,
    /// NTLM family.
    Ntlm,
    /// LM family.
    Lm,
    /// DES family.
    Des,
    /// AES family.
    Aes,
    /// Any other family.
    Other,
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

/// Metadata and behavior shared by every concrete hash type.
///
/// This trait is not object-safe because it has associated constants. The CLI
/// should dispatch through an enum or a static registry instead of
/// `dyn HashType`.
pub trait HashType {
    /// Human-readable name.
    const NAME: &'static str;
    /// Stable machine-readable identifier.
    const SLUG: &'static str;
    /// Algorithm family, if one applies.
    const FAMILY: Option<Family>;
    /// Metadata for every field.
    const FIELDS: &'static [Field];

    /// Every mode the type can ever support. Used by coverage and docs.
    const ALL_MODES: &'static [Mode];

    /// Modes that actually work for these values.
    ///
    /// The default returns [`Self::ALL_MODES`]. A type with value-dependent
    /// compatibility can override this method.
    fn modes(&self) -> Vec<Mode> {
        Self::ALL_MODES.to_vec()
    }

    /// Values for `--verbose` and JSON output.
    fn describe(&self) -> Vec<FieldValue>;
}

/// The target tool for rendering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tool {
    /// Hashcat.
    Hashcat,
    /// John the Ripper.
    John,
}

/// A hashcat version number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HashcatVersion(pub u16, pub u16, pub u16);

impl HashcatVersion {
    /// Newest version `omniex` knows about. Update when adding a reference.
    pub const NEWEST: Self = Self(8, 0, 0);
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
            hc_version: HashcatVersion::NEWEST,
        }
    }
}

/// Serializes a hash type into the string consumed by hashcat or John.
///
/// Implemented manually per hash type.
pub trait Render {
    /// Render the type using the given options.
    fn render(&self, opts: &RenderOptions) -> String;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Example;

    impl HashType for Example {
        const NAME: &'static str = "Example";
        const SLUG: &'static str = "example";
        const FAMILY: Option<Family> = Some(Family::Md5);
        const FIELDS: &'static [Field] = &[];
        const ALL_MODES: &'static [Mode] = &[Mode::Hashcat(0), Mode::John("raw-md5")];

        fn describe(&self) -> Vec<FieldValue> {
            Vec::new()
        }
    }

    #[test]
    fn modes_default_to_all_modes() {
        assert_eq!(
            Example.modes(),
            vec![Mode::Hashcat(0), Mode::John("raw-md5")]
        );
    }

    #[test]
    fn render_options_default_to_hashcat() {
        let opts = RenderOptions::default();

        assert_eq!(opts.tool, Tool::Hashcat);
        assert_eq!(opts.hc_version, HashcatVersion::NEWEST);
    }
}
