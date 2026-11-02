//! PKCS#12 / PFX bundle extraction.

use omniex::extract::{Artifact, ExtractError, Extracted, Extractor, Probe};
use omniex::types::{PfxJohn, Pkcs12};
use omniex::{HashType, HashValue};

const PKCS12_MAX_BYTES: u64 = 8 * 1024 * 1024;

const OID_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01];
const OID_SHA1: &[u8] = &[0x2b, 0x0e, 0x03, 0x02, 0x1a];
const OID_SHA224: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04];
const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
const OID_SHA384: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
const OID_SHA512: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];

/// PKCS#12 authenticated safe and MAC parameters.
struct Pkcs12Bundle {
    algorithm: DigestAlgorithm,
    iterations: u32,
    salt: Vec<u8>,
    data: Vec<u8>,
    mac: Vec<u8>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DigestAlgorithm {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl DigestAlgorithm {
    fn from_oid(oid: &[u8]) -> Option<Self> {
        match oid {
            OID_SHA1 => Some(Self::Sha1),
            OID_SHA224 => Some(Self::Sha224),
            OID_SHA256 => Some(Self::Sha256),
            OID_SHA384 => Some(Self::Sha384),
            OID_SHA512 => Some(Self::Sha512),
            _ => None,
        }
    }

    const fn numeric(self) -> u32 {
        match self {
            Self::Sha1 => 1,
            Self::Sha224 => 224,
            Self::Sha256 => 256,
            Self::Sha384 => 384,
            Self::Sha512 => 512,
        }
    }

    const fn key_length(self) -> u32 {
        match self {
            Self::Sha1 => 20,
            Self::Sha224 => 28,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    const fn pkcs12_version(self) -> u32 {
        match self {
            Self::Sha1 => 1,
            Self::Sha256 => 256,
            _ => 0,
        }
    }
}

struct Der<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Der<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    fn tlv(&mut self) -> Result<(u8, &'a [u8], &'a [u8]), ExtractError> {
        let start = self.pos;
        let tag = *self
            .data
            .get(self.pos)
            .ok_or_else(|| ExtractError::Invalid("truncated DER tag".to_owned()))?;
        self.pos += 1;
        let first = *self
            .data
            .get(self.pos)
            .ok_or_else(|| ExtractError::Invalid("truncated DER length".to_owned()))?;
        self.pos += 1;
        let length = if first < 0x80 {
            usize::from(first)
        } else {
            let count = usize::from(first & 0x7f);
            if count == 0 || count > 4 {
                return Err(ExtractError::Invalid("invalid DER length".to_owned()));
            }
            let mut length = 0usize;
            for _ in 0..count {
                let byte = *self
                    .data
                    .get(self.pos)
                    .ok_or_else(|| ExtractError::Invalid("truncated DER length".to_owned()))?;
                length = (length << 8) | usize::from(byte);
                self.pos += 1;
            }
            length
        };
        let end = self
            .pos
            .checked_add(length)
            .filter(|end| *end <= self.data.len())
            .ok_or_else(|| ExtractError::Invalid("DER value runs past the input".to_owned()))?;
        let value = &self.data[self.pos..end];
        self.pos = end;
        Ok((tag, value, &self.data[start..end]))
    }

    fn value(&mut self, tag: u8, what: &str) -> Result<&'a [u8], ExtractError> {
        let (actual, value, _) = self.tlv()?;
        if actual != tag {
            return Err(ExtractError::Invalid(format!("expected {what} DER tag")));
        }
        Ok(value)
    }

    fn sequence(&mut self) -> Result<Der<'a>, ExtractError> {
        Ok(Der::new(self.value(0x30, "SEQUENCE")?))
    }

    fn integer(&mut self, what: &str) -> Result<u32, ExtractError> {
        let value = self.value(0x02, what)?;
        if value.is_empty() || value.len() > 4 {
            return Err(ExtractError::Invalid(format!("invalid {what} integer")));
        }
        let mut number = 0u32;
        for byte in value {
            number = (number << 8) | u32::from(*byte);
        }
        Ok(number)
    }
}

fn parse_bundle(data: &[u8]) -> Result<Pkcs12Bundle, ExtractError> {
    let mut outer = Der::new(data);
    let mut pfx = outer.sequence()?;
    if pfx.integer("PFX version")? != 3 {
        return Err(ExtractError::Unsupported(
            "unsupported PFX version".to_owned(),
        ));
    }

    let mut auth_safe = pfx.sequence()?;
    let content_type = auth_safe.value(0x06, "authSafe content type")?;
    if content_type != OID_DATA {
        return Err(ExtractError::Unsupported(
            "PFX authSafe is not password protected".to_owned(),
        ));
    }
    let explicit = auth_safe.value(0xa0, "authSafe content")?;
    let auth_safe_data = Der::new(explicit).value(0x04, "authSafe content")?.to_vec();

    if pfx.is_empty() {
        return Err(ExtractError::Unsupported("PFX without a MAC".to_owned()));
    }

    let mut mac_data = pfx.sequence()?;
    let mut digest_info = mac_data.sequence()?;
    let mut algorithm = digest_info.sequence()?;
    let oid = algorithm.value(0x06, "MAC digest OID")?;
    let algorithm = DigestAlgorithm::from_oid(oid)
        .ok_or_else(|| ExtractError::Unsupported("unsupported PKCS#12 MAC digest".to_owned()))?;
    let mac = digest_info.value(0x04, "MAC digest")?.to_vec();
    let salt = mac_data.value(0x04, "MAC salt")?.to_vec();
    let iterations = if mac_data.is_empty() {
        1
    } else {
        mac_data.integer("MAC iteration count")?
    };

    if salt.is_empty() || mac.is_empty() || auth_safe_data.is_empty() {
        return Err(ExtractError::Invalid(
            "incomplete PKCS#12 MAC data".to_owned(),
        ));
    }

    Ok(Pkcs12Bundle {
        algorithm,
        iterations,
        salt,
        data: auth_safe_data,
        mac,
    })
}

fn read_primary(artifact: &Artifact) -> Result<Vec<u8>, ExtractError> {
    if artifact.primary().len() > PKCS12_MAX_BYTES {
        return Err(ExtractError::Unsupported(format!(
            "{} is larger than the PKCS#12 limit",
            artifact.label()
        )));
    }
    artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })
}

fn bundle(artifact: &Artifact) -> Result<Pkcs12Bundle, ExtractError> {
    parse_bundle(&read_primary(artifact)?)
}

pub struct Pkcs12Extractor;
pub struct PfxJohnExtractor;

impl Extractor for Pkcs12Extractor {
    fn slug(&self) -> &'static str {
        Pkcs12::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match bundle(artifact) {
            Ok(_) => Probe::yes("PKCS#12 PFX MAC structure"),
            Err(_) => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let bundle = bundle(artifact)?;
        let version = bundle.algorithm.pkcs12_version();
        if version == 0 {
            return Err(ExtractError::Unsupported(
                "hashcat does not support this PKCS#12 MAC digest".to_owned(),
            ));
        }
        Ok(vec![Box::new(Pkcs12 {
            version,
            iterations: bundle.iterations,
            salt_length: u32::try_from(bundle.salt.len())
                .map_err(|_| ExtractError::Invalid("PKCS#12 salt is too long".to_owned()))?,
            salt: bundle.salt,
            length: u32::try_from(bundle.data.len())
                .map_err(|_| ExtractError::Invalid("PKCS#12 data is too long".to_owned()))?,
            data: bundle.data,
            mac: bundle.mac,
        }) as Box<dyn HashValue>])
    }
}

impl Extractor for PfxJohnExtractor {
    fn slug(&self) -> &'static str {
        PfxJohn::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match bundle(artifact) {
            Ok(_) => Probe::yes("PKCS#12 PFX MAC structure"),
            Err(_) => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let bundle = bundle(artifact)?;
        let data = format!(
            "{}${}${}${}${}${}${}",
            bundle.algorithm.numeric(),
            bundle.algorithm.key_length(),
            bundle.iterations,
            bundle.salt.len(),
            omniex::format::hex(&bundle.salt),
            omniex::format::hex(&bundle.data),
            omniex::format::hex(&bundle.mac)
        );
        Ok(vec![Box::new(PfxJohn { data }) as Box<dyn HashValue>])
    }
}
