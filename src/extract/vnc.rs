//! VNC challenge-response extraction.

use std::collections::BTreeMap;

use super::wpa_pmkid::net;
use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Vnc;
use crate::{HashType, HashValue};

const VNC_PORT_START: u16 = 5900;
const VNC_PORT_END: u16 = 5999;
const CHALLENGE: usize = 16;

#[derive(Default)]
struct Stream {
    packets: Vec<(bool, Vec<u8>)>,
}

fn records(artifact: &Artifact) -> Result<Vec<Vnc>, ExtractError> {
    let source = artifact.primary();
    if !net::is_capture(source) {
        return Err(ExtractError::Unsupported("not a packet capture".to_owned()));
    }
    let mut streams: BTreeMap<(u16, u16), Stream> = BTreeMap::new();
    net::scan(source, |link_type, frame| {
        let Some((source_port, destination_port, payload)) = net::tcp_payload(link_type, frame)
        else {
            return;
        };
        if payload.is_empty() {
            return;
        }
        let server = if (VNC_PORT_START..=VNC_PORT_END).contains(&source_port) {
            source_port
        } else if (VNC_PORT_START..=VNC_PORT_END).contains(&destination_port) {
            destination_port
        } else {
            return;
        };
        let key = (
            source_port.min(destination_port),
            source_port.max(destination_port),
        );
        streams
            .entry(key)
            .or_default()
            .packets
            .push((source_port == server, payload.to_vec()));
    })?;

    let mut values = Vec::new();
    for stream in streams.values() {
        let mut banner = false;
        let mut challenge: Option<Vec<u8>> = None;
        for (from_server, payload) in &stream.packets {
            if !banner {
                if *from_server && payload.starts_with(b"RFB 003.") {
                    banner = true;
                }
                continue;
            }
            match &challenge {
                None if *from_server && payload.len() == CHALLENGE => {
                    challenge = Some(payload.clone());
                }
                None if *from_server && payload.len() == 4 + CHALLENGE => {
                    challenge = Some(payload[4..].to_vec());
                }
                Some(value) if !*from_server && payload.len() == CHALLENGE => {
                    let challenge: [u8; CHALLENGE] =
                        value.as_slice().try_into().expect("sixteen-byte challenge");
                    let response: [u8; CHALLENGE] = payload
                        .as_slice()
                        .try_into()
                        .expect("sixteen-byte response");
                    values.push(Vnc {
                        challenge,
                        response,
                    });
                    break;
                }
                _ => {}
            }
        }
    }
    if values.is_empty() {
        return Err(ExtractError::Unsupported(
            "no VNC challenge-response pair found".to_owned(),
        ));
    }
    Ok(values)
}

pub struct VncExtractor;

impl Extractor for VncExtractor {
    fn slug(&self) -> &'static str {
        Vnc::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match records(artifact) {
            Ok(_) => Probe::yes("VNC challenge-response exchange"),
            Err(_) => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(records(artifact)?
            .into_iter()
            .map(|value| Box::new(value) as Box<dyn HashValue>)
            .collect())
    }
}
