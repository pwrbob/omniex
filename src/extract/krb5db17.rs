//! Kerberos 5 etype 17 database extraction, plus the shared parser for
//! Kerberos database credential exports.

use omniex::extract::{Artifact, ExtractError, Extracted, Extractor, Probe};
use omniex::types::Krb5Db17;
use omniex::{HashType, HashValue};

const MAX_BYTES: u64 = 16 * 1024 * 1024;

const ETYPES: [u8; 5] = [1, 2, 3, 17, 18];

const HISTORY_GROUPS: [&str; 2] = ["OldCredentials", "OlderCredentials"];

pub(crate) struct KeyRecord {
    pub etype: u8,
    pub username: String,
    pub realm: String,
    pub key: Vec<u8>,
}

pub(crate) struct DbScan {
    pub keys: Vec<KeyRecord>,
    pub unsalted: Vec<u8>,
}

fn etype_of(label: &str) -> Option<u8> {
    let folded = label.to_ascii_lowercase().replace('-', "_");
    match folded.as_str() {
        "des_cbc_crc" | "dec_cbc_crc" => Some(1),
        "des_cbc_md4" => Some(2),
        "des_cbc_md5" => Some(3),
        "aes128_hmac" | "aes128_cts_hmac_sha1_96" => Some(17),
        "aes256_hmac" | "aes256_cts_hmac_sha1_96" => Some(18),
        _ => {
            let value = if let Some(hex) = label.strip_prefix("0x") {
                u8::from_str_radix(hex, 16).ok()?
            } else {
                label.parse::<u8>().ok()?
            };
            ETYPES.contains(&value).then_some(value)
        }
    }
}

fn key_length(etype: u8) -> usize {
    match etype {
        17 => 16,
        18 => 32,
        _ => 8,
    }
}

fn is_hex(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn decode_hex(value: &str, etype: u8) -> Result<Vec<u8>, ExtractError> {
    let expected = key_length(etype);
    let key = omniex::parse::decode_hex(value, 0)
        .map_err(|_| ExtractError::Invalid("invalid Kerberos key hex".to_owned()))?;
    if key.len() != expected {
        return Err(ExtractError::Invalid(format!(
            "Kerberos etype {etype} key is {} bytes, expected {expected}",
            key.len()
        )));
    }
    Ok(key)
}

fn group_name(line: &str) -> Option<&str> {
    let name = line.trim().strip_suffix(':').unwrap_or(line.trim());
    matches!(
        name,
        "Credentials" | "OldCredentials" | "OlderCredentials" | "ServiceCredentials"
    )
    .then_some(name)
}

fn account_name(line: &str) -> Option<&str> {
    let (name, value) = line.split_once(':')?;
    if !matches!(name.trim(), "SAM Username" | "User" | "SamAccountName") {
        return None;
    }
    let value = value.trim();
    (!value.is_empty() && !value.contains(char::is_whitespace)).then_some(value)
}

fn salt_line(line: &str) -> Option<&str> {
    let (name, value) = line.split_once(':')?;
    if !matches!(name.trim(), "Default Salt" | "Salt") {
        return None;
    }
    let value = value.trim();
    (!value.is_empty() && !value.contains(char::is_whitespace)).then_some(value)
}

fn labeled_key(line: &str) -> Option<(&str, &str)> {
    if !line.starts_with(char::is_whitespace) {
        return None;
    }
    let (label, value) = line.split_once(':')?;
    let label = label.trim();
    let label = match label.split_once('(') {
        Some((name, _)) => name.trim(),
        None => label,
    };
    let value = value.trim();
    (is_hex(value) && etype_of(label).is_some()).then_some((label, value))
}

fn key_value(line: &str) -> Option<&str> {
    if !line.starts_with(char::is_whitespace) {
        return None;
    }
    let (name, value) = line.split_once(':')?;
    if name.trim() != "Key" {
        return None;
    }
    let value = value.trim();
    is_hex(value).then_some(value)
}

fn etype_line(line: &str) -> Option<u8> {
    let label = line.trim();
    if label.is_empty()
        || !label
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return None;
    }
    etype_of(label)
}

fn split_salt<'a>(salt: &'a str, user: &str) -> Option<(&'a str, &'a str)> {
    if user.ends_with('$') || !user.is_ascii() || !salt.is_ascii() || salt.len() <= user.len() {
        return None;
    }
    let split = salt.len() - user.len();
    let principal = salt.get(split..)?;
    let realm = salt.get(..split)?;
    if realm.is_empty() || !principal.eq_ignore_ascii_case(user) {
        return None;
    }
    Some((principal, realm))
}

fn push_key(
    scan: &mut DbScan,
    user: &str,
    salt: &str,
    etype: u8,
    value: &str,
) -> Result<(), ExtractError> {
    let key = decode_hex(value, etype)?;
    let Some((principal, realm)) = split_salt(salt, user) else {
        scan.unsalted.push(etype);
        return Ok(());
    };
    if principal.contains('$')
        || realm.contains('$')
        || principal.contains(char::is_whitespace)
        || realm.contains(char::is_whitespace)
    {
        scan.unsalted.push(etype);
        return Ok(());
    }
    let record = KeyRecord {
        etype,
        username: principal.to_owned(),
        realm: realm.to_owned(),
        key,
    };
    if !scan.keys.iter().any(|existing| {
        existing.etype == record.etype
            && existing.username == record.username
            && existing.realm == record.realm
            && existing.key == record.key
    }) {
        scan.keys.push(record);
    }
    Ok(())
}

fn secretsdump_key(line: &str) -> Option<(u8, &str, &str)> {
    let (account, rest) = line.split_once(':')?;
    let (label, value) = rest.split_once(':')?;
    let user = account.rsplit_once('\\').map_or(account, |(_, user)| user);
    if user.is_empty()
        || user.contains(':')
        || user.contains(char::is_whitespace)
        || !is_hex(value.trim())
    {
        return None;
    }
    Some((etype_of(label)?, user, value.trim()))
}

fn ntdissector_key(line: &str) -> Option<u8> {
    if !line.trim_start().starts_with('{') || !line.contains("supplementalCredentials") {
        return None;
    }
    for label in [
        "aes128_hmac",
        "aes256_hmac",
        "aes128_cts_hmac_sha1_96",
        "aes256_cts_hmac_sha1_96",
        "des_cbc_crc",
        "des_cbc_md4",
        "des_cbc_md5",
    ] {
        if line.contains(label) {
            return etype_of(label);
        }
    }
    None
}

fn flush_pending(
    pending: &mut Vec<(u8, String)>,
    user: Option<&str>,
    salt: Option<&str>,
    scan: &mut DbScan,
) -> Result<(), ExtractError> {
    let Some(user) = user else {
        pending.clear();
        return Ok(());
    };
    if let Some(salt) = salt {
        for (etype, value) in pending.drain(..) {
            push_key(scan, user, salt, etype, &value)?;
        }
    } else {
        for (etype, _) in pending.drain(..) {
            scan.unsalted.push(etype);
        }
    }
    Ok(())
}

pub(crate) fn scan(artifact: &Artifact) -> Result<DbScan, ExtractError> {
    if artifact.primary().len() > MAX_BYTES {
        return Err(ExtractError::Unsupported(format!(
            "{} is larger than the Kerberos database limit",
            artifact.label()
        )));
    }
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    let text = std::str::from_utf8(&data).map_err(|_| {
        ExtractError::Unsupported("Kerberos database export is not text".to_owned())
    })?;

    let mut scan = DbScan {
        keys: Vec::new(),
        unsalted: Vec::new(),
    };
    let mut user: Option<String> = None;
    let mut salt: Option<String> = None;
    let mut group: Option<String> = None;
    let mut pending_etype: Option<u8> = None;
    let mut pending: Vec<(u8, String)> = Vec::new();

    for line in text.lines() {
        if let Some(name) = account_name(line) {
            flush_pending(&mut pending, user.as_deref(), salt.as_deref(), &mut scan)?;
            user = Some(name.to_owned());
            salt = None;
            group = None;
            pending_etype = None;
            continue;
        }

        if let Some(name) = group_name(line) {
            group = Some(name.to_owned());
            continue;
        }

        if let Some(value) = salt_line(line) {
            if line
                .split_once(':')
                .is_some_and(|(name, _)| name.trim() == "Salt")
            {
                flush_pending(&mut pending, user.as_deref(), Some(value), &mut scan)?;
            } else {
                salt = Some(value.to_owned());
            }
            continue;
        }

        if let Some((label, value)) = labeled_key(line) {
            let Some(etype) = etype_of(label) else {
                continue;
            };
            let Some(user) = user.as_deref() else {
                scan.unsalted.push(etype);
                continue;
            };
            if group
                .as_deref()
                .is_some_and(|group| HISTORY_GROUPS.contains(&group))
            {
                continue;
            }
            if let Some(salt) = salt.as_deref() {
                push_key(&mut scan, user, salt, etype, value)?;
            } else {
                pending.push((etype, value.to_owned()));
            }
            continue;
        }

        if let Some(etype) = etype_line(line) {
            pending_etype = Some(etype);
            continue;
        }

        if let Some(value) = key_value(line) {
            let Some(etype) = pending_etype else {
                continue;
            };
            if user.is_none() {
                scan.unsalted.push(etype);
                continue;
            }
            if group
                .as_deref()
                .is_some_and(|group| HISTORY_GROUPS.contains(&group))
            {
                continue;
            }
            pending.push((etype, value.to_owned()));
            continue;
        }

        if let Some((etype, user, _)) = secretsdump_key(line) {
            if !user.ends_with('$') {
                scan.unsalted.push(etype);
            }
            continue;
        }

        if let Some(etype) = ntdissector_key(line) {
            scan.unsalted.push(etype);
        }
    }
    flush_pending(&mut pending, user.as_deref(), salt.as_deref(), &mut scan)?;

    Ok(scan)
}

pub(crate) fn probe_for(artifact: &Artifact, etypes: &[u8]) -> Probe {
    match scan(artifact) {
        Ok(scan) => {
            if scan
                .keys
                .iter()
                .any(|record| etypes.contains(&record.etype))
            {
                Probe::yes("Kerberos database key")
            } else if scan.unsalted.iter().any(|etype| etypes.contains(etype)) {
                Probe::maybe("Kerberos database keys without a derivable realm")
            } else {
                Probe::No
            }
        }
        Err(ExtractError::Unsupported(_)) => Probe::No,
        Err(ExtractError::Invalid(reason)) => Probe::maybe(reason),
    }
}

pub(crate) fn records(artifact: &Artifact, etypes: &[u8]) -> Result<Vec<KeyRecord>, ExtractError> {
    let scan = scan(artifact)?;
    let records: Vec<KeyRecord> = scan
        .keys
        .into_iter()
        .filter(|record| etypes.contains(&record.etype))
        .collect();
    if records.is_empty() {
        return Err(ExtractError::Unsupported(
            "no Kerberos database keys with a derivable realm".to_owned(),
        ));
    }
    Ok(records)
}

pub struct Krb5Db17Extractor;

impl Extractor for Krb5Db17Extractor {
    fn slug(&self) -> &'static str {
        Krb5Db17::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        probe_for(artifact, &[17])
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let records = records(artifact, &[17])?;
        let mut extracted = Vec::with_capacity(records.len());
        for record in records {
            let digest: [u8; 16] = record.key.try_into().map_err(|_| {
                ExtractError::Invalid("Kerberos etype 17 key is not 16 bytes".to_owned())
            })?;
            extracted.push(Box::new(Krb5Db17 {
                username: record.username,
                realm: record.realm,
                digest,
            }) as Box<dyn HashValue>);
        }
        Ok(extracted)
    }
}
