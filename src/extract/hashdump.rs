//! Password hashes embedded in text dumps, exports, and binary profile dumps.

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::{
    As400Des, As400Ssha1, LotusNotes, Openvms, Oracle11, Oracle12c, OracleOtm, RacfKdfaes,
    RacfPassphrase, SybaseProp,
};
use crate::{HashType, HashValue, Parse, ParseOptions};

const AS400_PROFILE_SIZE: usize = 2000;
const AS400_PROFILE_MIN: usize = 73;
const AS400_PROFILE_FIXED: [u8; 2] = [0x40, 0xf0];
const AS400_PROFILE_FIXED_OFFSET: usize = 94;
const AS400_USER_OFFSET: usize = 8;
const AS400_USER_LEN: usize = 10;
const AS400_FORMAT_OFFSET: usize = 18;
const AS400_MARKER_OFFSET: usize = 52;
const AS400_MARKER: u8 = 0x05;
const AS400_DES_OFFSET: usize = 19;
const AS400_DES_LEN: usize = 16;
const AS400_SHA1_OFFSET: usize = 53;
const AS400_SHA1_LEN: usize = 20;
const AS400_OPAQUE_OFFSET: usize = 96;
const AS400_OPAQUE_END: usize = 288;
const AS400_DIGEST_OFFSET: usize = 1980;
const AS400_DIGEST_END: usize = 2000;
const LOTUS_G_LEN: usize = 19;
const LOTUS_H_LEN: usize = 48;

fn data(artifact: &Artifact) -> Result<Vec<u8>, ExtractError> {
    artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })
}

fn tokens(data: &[u8]) -> Result<Vec<String>, ExtractError> {
    let text = std::str::from_utf8(data)
        .map_err(|_| ExtractError::Invalid("hash dump is not UTF-8".to_owned()))?;
    Ok(text
        .split_whitespace()
        .map(|token| token.trim_matches(|character| matches!(character, '\'' | '"' | ',' | ';')))
        .filter(|token| !token.is_empty())
        .map(str::to_owned)
        .collect())
}

fn text_hashes<T>(data: &[u8]) -> Vec<T>
where
    T: Parse + HashValue,
{
    let opts = ParseOptions::default();
    tokens(data)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|token| T::parse(&token, &opts).ok())
        .collect()
}

fn cp037_user(field: &[u8]) -> Option<String> {
    let mut user = String::new();
    for (index, byte) in field.iter().enumerate() {
        let character = match byte {
            0x40 => {
                if field[index..].iter().any(|padding| *padding != 0x40) {
                    return None;
                }
                break;
            }
            0xc1..=0xc9 => char::from(b'A' + (byte - 0xc1)),
            0xd1..=0xd9 => char::from(b'J' + (byte - 0xd1)),
            0xe2..=0xe9 => char::from(b'S' + (byte - 0xe2)),
            0xf0..=0xf9 => char::from(b'0' + (byte - 0xf0)),
            0x7c => '@',
            0x7b => '#',
            0x5b => '$',
            0x6d => '_',
            0x4b => '.',
            _ => return None,
        };
        user.push(character);
    }
    (!user.is_empty()).then_some(user)
}

fn blank(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0x00 || *byte == 0x40)
}

#[derive(PartialEq, Eq)]
struct Profile {
    user: String,
    des: Vec<[u8; 8]>,
    sha1: Option<[u8; 20]>,
}

fn profile_at(data: &[u8], start: usize) -> Result<Profile, ExtractError> {
    let available = data.len().saturating_sub(start);
    if available < AS400_PROFILE_MIN {
        return Err(ExtractError::Unsupported(
            "AS/400 user profile is too short".to_owned(),
        ));
    }
    let profile = &data[start..start + available.min(AS400_PROFILE_SIZE)];
    let returned = u32::from_be_bytes([profile[0], profile[1], profile[2], profile[3]]) as usize;
    let length = u32::from_be_bytes([profile[4], profile[5], profile[6], profile[7]]) as usize;
    if !(AS400_PROFILE_MIN..=AS400_PROFILE_SIZE).contains(&length)
        || returned < AS400_PROFILE_MIN
        || returned > length
        || profile.len() < returned
    {
        return Err(ExtractError::Invalid(
            "invalid AS/400 user profile length".to_owned(),
        ));
    }
    if profile.get(AS400_MARKER_OFFSET) != Some(&AS400_MARKER) {
        return Err(ExtractError::Invalid(
            "invalid AS/400 user profile marker".to_owned(),
        ));
    }
    let format = profile[AS400_FORMAT_OFFSET];
    if !matches!(format, b'D' | b'T') {
        return Err(ExtractError::Invalid(
            "unknown AS/400 user profile format".to_owned(),
        ));
    }
    if let Some(fixed) = profile.get(AS400_PROFILE_FIXED_OFFSET..AS400_PROFILE_FIXED_OFFSET + 2)
        && fixed != AS400_PROFILE_FIXED
    {
        return Err(ExtractError::Invalid(
            "invalid AS/400 user profile header".to_owned(),
        ));
    }
    let user = cp037_user(&profile[AS400_USER_OFFSET..AS400_USER_OFFSET + AS400_USER_LEN])
        .ok_or_else(|| ExtractError::Invalid("invalid AS/400 user profile name".to_owned()))?;

    let opaque = profile
        .get(AS400_OPAQUE_OFFSET..AS400_OPAQUE_END)
        .map(blank)
        .unwrap_or(true);
    let digest = profile
        .get(AS400_DIGEST_OFFSET..AS400_DIGEST_END)
        .map(blank)
        .unwrap_or(true);
    if !opaque || !digest {
        return Err(ExtractError::Unsupported(
            "AS/400 user profile uses wrapped verifier areas".to_owned(),
        ));
    }

    let mut des = Vec::new();
    for slot in profile[AS400_DES_OFFSET..AS400_DES_OFFSET + AS400_DES_LEN].chunks_exact(8) {
        if slot.iter().all(|byte| *byte == 0x40) {
            continue;
        }
        let mut digest = [0u8; 8];
        digest.copy_from_slice(slot);
        des.push(digest);
    }

    let sha1 = match profile.get(AS400_SHA1_OFFSET..AS400_SHA1_OFFSET + AS400_SHA1_LEN) {
        Some(area) if !area.iter().all(|byte| *byte == 0x40) => {
            let mut digest = [0u8; AS400_SHA1_LEN];
            digest.copy_from_slice(area);
            Some(digest)
        }
        _ => None,
    };

    if des.is_empty() && sha1.is_none() {
        return Err(ExtractError::Unsupported(
            "AS/400 user profile has no verifiers".to_owned(),
        ));
    }
    Ok(Profile { user, des, sha1 })
}

fn profiles(data: &[u8]) -> Vec<Profile> {
    let mut found: Vec<Profile> = Vec::new();
    let mut index = 0;
    while index + AS400_PROFILE_FIXED_OFFSET + AS400_PROFILE_FIXED.len() <= data.len() {
        let Some(position) = data[index..]
            .windows(AS400_PROFILE_FIXED.len())
            .position(|window| window == AS400_PROFILE_FIXED)
        else {
            break;
        };
        let anchor = index + position;
        if let Some(start) = anchor.checked_sub(AS400_PROFILE_FIXED_OFFSET)
            && let Ok(profile) = profile_at(data, start)
            && !found.contains(&profile)
        {
            found.push(profile);
        }
        index = anchor + 1;
    }
    if found.is_empty()
        && let Ok(profile) = profile_at(data, 0)
    {
        found.push(profile);
    }
    found
}

fn as400_des(data: &[u8]) -> Vec<As400Des> {
    let mut hashes = text_hashes::<As400Des>(data);
    for profile in profiles(data) {
        for digest in profile.des {
            hashes.push(As400Des {
                salt: profile.user.clone(),
                digest,
            });
        }
    }
    hashes
}

fn as400_ssha1(data: &[u8]) -> Vec<As400Ssha1> {
    let mut hashes = text_hashes::<As400Ssha1>(data);
    for profile in profiles(data) {
        if let Some(digest) = profile.sha1 {
            hashes.push(As400Ssha1 {
                user: profile.user.clone(),
                digest,
            });
        }
    }
    hashes
}

fn lotus64(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/')
}

fn lotus_shape(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.first() != Some(&b'(') || bytes.last() != Some(&b')') {
        return false;
    }
    let width = match bytes.get(1) {
        Some(b'G') => LOTUS_G_LEN,
        Some(b'H') => LOTUS_H_LEN,
        _ => return false,
    };
    bytes.len() == width + 3 && bytes[2..2 + width].iter().all(|byte| lotus64(*byte))
}

fn lotus_notes(data: &[u8]) -> Vec<LotusNotes> {
    let mut hashes: Vec<LotusNotes> = text_hashes::<LotusNotes>(data)
        .into_iter()
        .filter(|hash| lotus_shape(&hash.value))
        .collect();
    let mut seen: Vec<String> = hashes.iter().map(|hash| hash.value.clone()).collect();
    for (index, byte) in data.iter().enumerate() {
        if *byte != b'(' {
            continue;
        }
        let width = match data.get(index + 1) {
            Some(b'G') => LOTUS_G_LEN,
            Some(b'H') => LOTUS_H_LEN,
            _ => continue,
        };
        let start = index + 2;
        let end = start + width;
        let Some(payload) = data.get(start..end) else {
            continue;
        };
        if !payload.iter().all(|byte| lotus64(*byte)) || data.get(end) != Some(&b')') {
            continue;
        }
        let value = String::from_utf8_lossy(&data[index..=end]).into_owned();
        if seen.contains(&value) {
            continue;
        }
        seen.push(value.clone());
        hashes.push(LotusNotes { value });
    }
    hashes
}

fn extract<T>(artifact: &Artifact) -> Result<Vec<T>, ExtractError>
where
    T: Parse + HashValue + 'static,
{
    let hashes = {
        let opts = ParseOptions::default();
        tokens(&data(artifact)?)?
            .into_iter()
            .filter_map(|token| T::parse(&token, &opts).ok())
            .collect::<Vec<T>>()
    };
    if hashes.is_empty() {
        return Err(ExtractError::Unsupported(
            "no matching password hashes found".to_owned(),
        ));
    }
    Ok(hashes)
}

fn probe<T>(artifact: &Artifact) -> Probe
where
    T: Parse + HashValue + 'static,
{
    match extract::<T>(artifact) {
        Ok(_) => Probe::yes("password hash token"),
        Err(_) => Probe::No,
    }
}

macro_rules! dump_extractor {
    ($name:ident, $ty:ty) => {
        pub struct $name;
        impl Extractor for $name {
            fn slug(&self) -> &'static str {
                <$ty>::SLUG
            }
            fn probe(&self, artifact: &Artifact) -> Probe {
                probe::<$ty>(artifact)
            }
            fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
                Ok(extract::<$ty>(artifact)?
                    .into_iter()
                    .map(|hash| Box::new(hash) as Box<dyn HashValue>)
                    .collect())
            }
        }
    };
}

fn boxed<T>(hashes: Vec<T>) -> Extracted
where
    T: HashValue + 'static,
{
    hashes
        .into_iter()
        .map(|hash| Box::new(hash) as Box<dyn HashValue>)
        .collect()
}

/// Extractor for AS/400 DES hashes in text dumps and `QSYRUPWD` UPWD0100
/// user profile buffers.
///
/// A profile whose verifier areas are wrapped is rejected rather than treated
/// as a legacy verifier, because the wrapping key is not available to this
/// extractor.
pub struct As400DesExtractor;

impl Extractor for As400DesExtractor {
    fn slug(&self) -> &'static str {
        As400Des::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match data(artifact) {
            Ok(data) if !as400_des(&data).is_empty() => Probe::yes("AS/400 DES password hash"),
            _ => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let data = data(artifact)?;
        let hashes = as400_des(&data);
        if hashes.is_empty() {
            return Err(ExtractError::Unsupported(
                "no AS/400 DES password hashes found".to_owned(),
            ));
        }
        Ok(boxed(hashes))
    }
}

/// Extractor for AS/400 SHA1 hashes in text dumps and `QSYRUPWD` UPWD0100
/// user profile buffers.
///
/// A profile whose verifier areas are wrapped is rejected for the same reason
/// as the DES extractor.
pub struct As400Ssha1Extractor;

impl Extractor for As400Ssha1Extractor {
    fn slug(&self) -> &'static str {
        As400Ssha1::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match data(artifact) {
            Ok(data) if !as400_ssha1(&data).is_empty() => Probe::yes("AS/400 SHA1 password hash"),
            _ => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let data = data(artifact)?;
        let hashes = as400_ssha1(&data);
        if hashes.is_empty() {
            return Err(ExtractError::Unsupported(
                "no AS/400 SHA1 password hashes found".to_owned(),
            ));
        }
        Ok(boxed(hashes))
    }
}

/// Extractor for Lotus Notes/Domino 6 and 8 hashes in text dumps and user ID
/// files. Only a complete `(G...)` or `(H...)` password digest is accepted.
pub struct LotusNotesExtractor;

impl Extractor for LotusNotesExtractor {
    fn slug(&self) -> &'static str {
        LotusNotes::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match data(artifact) {
            Ok(data) if !lotus_notes(&data).is_empty() => {
                Probe::yes("Lotus Notes/Domino password digest")
            }
            _ => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let data = data(artifact)?;
        let hashes = lotus_notes(&data);
        if hashes.is_empty() {
            return Err(ExtractError::Unsupported(
                "no Lotus Notes/Domino password digests found".to_owned(),
            ));
        }
        Ok(boxed(hashes))
    }
}

dump_extractor!(OpenvmsExtractor, Openvms);
dump_extractor!(Oracle11Extractor, Oracle11);
dump_extractor!(Oracle12cExtractor, Oracle12c);
dump_extractor!(OracleOtmExtractor, OracleOtm);
dump_extractor!(RacfKdfaesExtractor, RacfKdfaes);
dump_extractor!(RacfPassphraseExtractor, RacfPassphrase);
dump_extractor!(SybasePropExtractor, SybaseProp);
