//! PPP and iSCSI CHAP exchange extraction.
//!
//! PPP CHAP packets are shared with the MSCHAPv2 extractor, so the PPP reader
//! lives in [`ppp`]. iSCSI login PDUs carry the same CHAP fields in their text
//! key/value data segment.

use std::collections::BTreeSet;

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Chap;
use crate::{HashType, HashValue};

pub(crate) mod ppp {
    //! Reads PPP CHAP challenge and response packets from captures.

    use super::super::{Artifact, ExtractError};
    use crate::extract::wpa_pmkid::net;

    const PPP_PROTOCOL: [u8; 2] = [0xc2, 0x23];
    const MAX_RAW_ARTIFACT: u64 = 64 * 1024 * 1024;

    const CHALLENGE: u8 = 1;
    const RESPONSE: u8 = 2;

    #[derive(Debug, Clone)]
    pub(crate) struct Exchange {
        pub(crate) id: u8,
        pub(crate) challenge: Vec<u8>,
        pub(crate) response: Vec<u8>,
        pub(crate) name: String,
    }

    enum Event {
        Challenge {
            id: u8,
            value: Vec<u8>,
        },
        Response {
            id: u8,
            value: Vec<u8>,
            name: String,
        },
    }

    fn truncated() -> ExtractError {
        ExtractError::Invalid("truncated PPP CHAP packet".to_owned())
    }

    fn marker(frame: &[u8]) -> Option<usize> {
        if frame.starts_with(&PPP_PROTOCOL) {
            return Some(0);
        }
        if frame.len() >= 4 && frame[..2] == [0xff, 0x03] && frame[2..4] == PPP_PROTOCOL {
            return Some(2);
        }
        if frame.len() >= 22 && frame[12..14] == [0x88, 0x64] && frame[20..22] == PPP_PROTOCOL {
            return Some(20);
        }
        None
    }

    fn parse_frame(frame: &[u8], events: &mut Vec<Event>) -> Result<(), ExtractError> {
        let Some(offset) = marker(frame) else {
            return Ok(());
        };
        let start = offset + PPP_PROTOCOL.len();
        let header = frame.get(start..start + 5).ok_or_else(truncated)?;
        let code = header[0];
        let id = header[1];
        let length = usize::from(u16::from_be_bytes([header[2], header[3]]));
        let value_size = usize::from(header[4]);
        if length < 5 {
            return Err(truncated());
        }
        let end = start.checked_add(length).ok_or_else(truncated)?;
        if end > frame.len() || value_size > length - 5 {
            return Err(truncated());
        }
        let value_end = start + 5 + value_size;
        let value = frame.get(start + 5..value_end).ok_or_else(truncated)?;
        let name =
            String::from_utf8_lossy(frame.get(value_end..end).unwrap_or_default()).into_owned();
        match code {
            CHALLENGE => events.push(Event::Challenge {
                id,
                value: value.to_vec(),
            }),
            RESPONSE => events.push(Event::Response {
                id,
                value: value.to_vec(),
                name,
            }),
            _ => {}
        }
        Ok(())
    }

    fn events(artifact: &Artifact) -> Result<Vec<Event>, ExtractError> {
        let source = artifact.primary();
        let mut events = Vec::new();
        if net::is_capture(source) {
            let mut failure = None;
            net::scan(source, |_, packet| {
                if failure.is_some() {
                    return;
                }
                if let Err(error) = parse_frame(packet, &mut events) {
                    failure = Some(error);
                }
            })?;
            if let Some(error) = failure {
                return Err(error);
            }
        } else {
            if source.len() > MAX_RAW_ARTIFACT {
                return Err(ExtractError::Unsupported(
                    "PPP CHAP artifact is too large".to_owned(),
                ));
            }
            let data = source.read_all().map_err(|error| {
                ExtractError::Invalid(format!("cannot read PPP CHAP artifact: {error}"))
            })?;
            parse_frame(&data, &mut events)?;
        }
        Ok(events)
    }

    /// Decodes every PPP CHAP challenge/response pair in the artifact.
    pub(crate) fn exchanges(artifact: &Artifact) -> Result<Vec<Exchange>, ExtractError> {
        let mut result = Vec::new();
        let mut challenge = None;
        for event in events(artifact)? {
            match event {
                Event::Challenge { id, value } => challenge = Some((id, value)),
                Event::Response { id, value, name } => {
                    let Some((challenge_id, challenge_value)) = &challenge else {
                        continue;
                    };
                    if *challenge_id != id {
                        continue;
                    }
                    result.push(Exchange {
                        id,
                        challenge: challenge_value.clone(),
                        response: value,
                        name,
                    });
                }
            }
        }
        Ok(result)
    }
}

mod iscsi {
    //! Reads CHAP key/value fields from iSCSI login PDUs.

    use super::super::{Artifact, ExtractError};
    use crate::extract::wpa_pmkid::net;

    const MAX_RAW_ARTIFACT: u64 = 64 * 1024 * 1024;

    pub(super) struct Exchange {
        pub(super) id: u8,
        pub(super) challenge: Vec<u8>,
        pub(super) response: Vec<u8>,
    }

    type Event = (u8, Vec<u8>, Vec<u8>);

    fn field<'a>(data: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
        let mut offset = 0;
        while let Some(found) = data[offset..]
            .windows(name.len())
            .position(|window| window == name)
        {
            let start = offset + found;
            let boundary = start == 0 || data[start - 1] == 0;
            if boundary {
                let value_start = start + name.len();
                let value_end = data[value_start..]
                    .iter()
                    .position(|byte| *byte == 0)
                    .map_or(data.len(), |length| value_start + length);
                return data.get(value_start..value_end);
            }
            offset = start + name.len();
        }
        None
    }

    fn hex(value: &[u8]) -> Result<Vec<u8>, ExtractError> {
        let value = value
            .strip_prefix(b"0x")
            .or_else(|| value.strip_prefix(b"0X"))
            .unwrap_or(value);
        if !value.len().is_multiple_of(2) {
            return Err(ExtractError::Invalid(
                "odd-length iSCSI CHAP value".to_owned(),
            ));
        }
        let mut bytes = Vec::with_capacity(value.len() / 2);
        for pair in value.chunks_exact(2) {
            let text = std::str::from_utf8(pair)
                .map_err(|_| ExtractError::Invalid("non-text iSCSI CHAP value".to_owned()))?;
            bytes.push(
                u8::from_str_radix(text, 16).map_err(|_| {
                    ExtractError::Invalid("invalid iSCSI CHAP hex value".to_owned())
                })?,
            );
        }
        Ok(bytes)
    }

    fn frame(frame: &[u8], events: &mut Vec<Event>) -> Result<(), ExtractError> {
        if let (Some(id), Some(challenge)) = (field(frame, b"CHAP_I="), field(frame, b"CHAP_C=")) {
            let id = std::str::from_utf8(id)
                .ok()
                .and_then(|value| value.parse::<u8>().ok())
                .ok_or_else(|| ExtractError::Invalid("invalid iSCSI CHAP identifier".to_owned()))?;
            events.push((id, hex(challenge)?, Vec::new()));
        }
        if let Some(response) = field(frame, b"CHAP_R=") {
            let response = hex(response)?;
            if let Some(last) = events.last_mut() {
                last.2 = response;
            }
        }
        Ok(())
    }

    fn events(artifact: &Artifact) -> Result<Vec<Event>, ExtractError> {
        let source = artifact.primary();
        let mut events = Vec::new();
        if net::is_capture(source) {
            let mut failure = None;
            net::scan(source, |_, packet| {
                if failure.is_some() {
                    return;
                }
                if let Err(error) = frame(packet, &mut events) {
                    failure = Some(error);
                }
            })?;
            if let Some(error) = failure {
                return Err(error);
            }
        } else {
            if source.len() > MAX_RAW_ARTIFACT {
                return Err(ExtractError::Unsupported(
                    "iSCSI CHAP artifact is too large".to_owned(),
                ));
            }
            let data = source.read_all().map_err(|error| {
                ExtractError::Invalid(format!("cannot read iSCSI CHAP artifact: {error}"))
            })?;
            frame(&data, &mut events)?;
        }
        Ok(events)
    }

    pub(super) fn exchanges(artifact: &Artifact) -> Result<Vec<Exchange>, ExtractError> {
        Ok(events(artifact)?
            .into_iter()
            .filter_map(|(id, challenge, response)| {
                (!challenge.is_empty() && !response.is_empty()).then_some(Exchange {
                    id,
                    challenge,
                    response,
                })
            })
            .collect())
    }
}

pub struct ChapExtractor;

fn value(kind: u8, challenge: &[u8], response: &[u8]) -> Option<Chap> {
    Some(Chap {
        kind,
        challenge: challenge.try_into().ok()?,
        response: response.try_into().ok()?,
    })
}

fn values(artifact: &Artifact) -> Result<Vec<Chap>, ExtractError> {
    let mut records = BTreeSet::new();
    for exchange in ppp::exchanges(artifact)? {
        if exchange.challenge.len() == 16
            && exchange.response.len() == 16
            && let Some(chap) = value(exchange.id, &exchange.challenge, &exchange.response)
        {
            records.insert((chap.kind, chap.challenge, chap.response));
        }
    }
    for exchange in iscsi::exchanges(artifact)? {
        if exchange.challenge.len() == 16
            && exchange.response.len() == 16
            && let Some(chap) = value(exchange.id, &exchange.challenge, &exchange.response)
        {
            records.insert((chap.kind, chap.challenge, chap.response));
        }
    }
    Ok(records
        .into_iter()
        .map(|(kind, challenge, response)| Chap {
            kind,
            challenge,
            response,
        })
        .collect())
}

impl Extractor for ChapExtractor {
    fn slug(&self) -> &'static str {
        Chap::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match (ppp::exchanges(artifact), iscsi::exchanges(artifact)) {
            (Ok(ppp), Ok(iscsi)) => {
                let ppp_match = ppp
                    .iter()
                    .any(|value| value.challenge.len() == 16 && value.response.len() == 16);
                let iscsi_match = iscsi
                    .iter()
                    .any(|value| value.challenge.len() == 16 && value.response.len() == 16);
                if ppp_match || iscsi_match {
                    Probe::yes("CHAP challenge-response")
                } else {
                    Probe::No
                }
            }
            (Err(ExtractError::Invalid(reason)), _) | (_, Err(ExtractError::Invalid(reason))) => {
                Probe::maybe(reason)
            }
            _ => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let values = values(artifact)?;
        if values.is_empty() {
            return Err(ExtractError::Unsupported(
                "no CHAP challenge-response exchanges".to_owned(),
            ));
        }
        Ok(values
            .into_iter()
            .map(|value| Box::new(value) as Box<dyn HashValue>)
            .collect())
    }
}
