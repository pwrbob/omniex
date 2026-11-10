//! VNC challenge-response extraction.

use omniex::extract::{self, Artifact, Probe};
use omniex::{RenderOptions, Tool};

fn frame(source_port: u16, destination_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut data = vec![0u8; 14 + 20 + 20 + payload.len()];
    data[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    let total = (20 + 20 + payload.len()) as u16;
    data[14] = 0x45;
    data[16..18].copy_from_slice(&total.to_be_bytes());
    data[22] = 64;
    data[23] = 6;
    data[26..30].copy_from_slice(&[10, 0, 0, 1]);
    data[30..34].copy_from_slice(&[10, 0, 0, 2]);
    data[34..36].copy_from_slice(&source_port.to_be_bytes());
    data[36..38].copy_from_slice(&destination_port.to_be_bytes());
    data[46] = 0x50;
    data[config_payload_offset()..].copy_from_slice(payload);
    data
}

fn config_payload_offset() -> usize {
    14 + 20 + 20
}

fn capture(packets: &[(u16, u16, &[u8])], trailing: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    data.extend_from_slice(&2u16.to_le_bytes());
    data.extend_from_slice(&4u16.to_le_bytes());
    data.extend_from_slice(&[0; 8]);
    data.extend_from_slice(&65535u32.to_le_bytes());
    data.extend_from_slice(&1u32.to_le_bytes());
    for (source, destination, payload) in packets {
        let frame = frame(*source, *destination, payload);
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        data.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        data.extend_from_slice(&frame);
    }
    data.extend_from_slice(trailing);
    data
}

fn vnc_capture(trailing: &[u8]) -> Vec<u8> {
    let challenge = [0x11u8; 16];
    let response = [0x22u8; 16];
    let mut security = vec![0, 0, 0, 2];
    security.extend_from_slice(&challenge);
    capture(
        &[
            (5900, 59000, b"RFB 003.003\n"),
            (59000, 5900, b"RFB 003.003\n"),
            (5900, 59000, &security),
            (59000, 5900, &response),
        ],
        trailing,
    )
}

#[test]
fn vnc_extracts_a_challenge_response_pair() {
    let extractor = extract::by_slug("vnc").expect("extractor");
    let artifact = Artifact::from_bytes("vnc.pcap", vnc_capture(&[]));
    assert!(matches!(extractor.probe(&artifact), Probe::Yes(_)));
    let values = extractor.extract(&artifact).expect("extract");
    assert_eq!(
        values[0]
            .render(&RenderOptions {
                tool: Tool::John,
                ..RenderOptions::default()
            })
            .unwrap(),
        format!("$vnc$*{}*{}", "11".repeat(16), "22".repeat(16))
    );
}

#[test]
fn vnc_tolerates_a_trailing_partial_pcap_record() {
    let extractor = extract::by_slug("vnc").expect("extractor");
    assert!(
        extractor
            .extract(&Artifact::from_bytes("vnc.pcap", vnc_capture(&[0])))
            .is_ok()
    );
    assert!(
        extractor
            .extract(&Artifact::from_bytes("empty", Vec::new()))
            .is_err()
    );
}
