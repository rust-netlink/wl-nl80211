// SPDX-License-Identifier: MIT

use crate::{
    Ieee80211AuthAlgorithm, Ieee80211AuthFrame, Ieee80211AuthFrameSae,
    Ieee80211StatusCode,
};

#[test]
fn roundtrip_sae_commit_frame() {
    let sta = [0x02u8; 6];
    let ap = [0x01u8; 6];
    let payload = b"0123456789abcdef0123456789abcdef".to_vec();
    let sae = Ieee80211AuthFrameSae::new(
        sta,
        ap,
        1,
        Ieee80211StatusCode::Success,
        payload,
    );
    let frame = sae.to_bytes();
    assert!(frame.len() > 24);
    let parsed =
        Ieee80211AuthFrame::parse_sae(&frame).expect("parse SAE frame");
    assert_eq!(sae, parsed);
    assert_eq!(parsed.transaction, 1);
    assert_eq!(parsed.status_code, Ieee80211StatusCode::Success);
    assert_eq!(parsed.da, ap);
    assert_eq!(parsed.sa, sta);
    assert_eq!(parsed.bssid, ap);
    assert_eq!(parsed.sta_mac(), sta);
}

#[test]
fn parse_wrong_auth_alg() {
    let frame = Ieee80211AuthFrameSae::new(
        [0u8; 6],
        [0u8; 6],
        1,
        Ieee80211StatusCode::Success,
        vec![],
    )
    .to_bytes();
    let mut modified = frame.clone();
    modified[24] = 0;
    modified[25] = 1;
    assert!(Ieee80211AuthFrame::parse_sae(&modified).is_none());
}

#[test]
fn parse_too_short() {
    assert!(Ieee80211AuthFrame::parse_sae(&[0u8; 10]).is_none());
}

#[test]
fn auth_frame_sae_accessors() {
    let sta = [0x02u8; 6];
    let ap = [0x01u8; 6];
    let payload = b"0123456789abcdef".to_vec();
    let frame = Ieee80211AuthFrameSae::new(
        sta,
        ap,
        2,
        Ieee80211StatusCode::Success,
        payload.clone(),
    )
    .to_bytes();
    let parsed = Ieee80211AuthFrame::parse(&frame).expect("parse");
    assert_eq!(Ieee80211AuthAlgorithm::Sae, parsed.algorithm());
    assert!(parsed.is_sae());
    let sae = parsed.sae().expect("SAE frame");
    assert_eq!(payload.as_slice(), sae.body());
    assert_eq!(sta, sae.sta_mac());
    assert_eq!(ap, sae.bssid);
}

#[test]
fn parse_captured_sae_commit_frame() {
    // SAE Authentication frame (transaction 1, status success) from the
    // same nl80211 capture as test_captured_authenticate_event.
    let raw = vec![
        0xb0, 0x00, 0x3a, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0xe0, 0x00,
        0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x13, 0x00, 0xa4, 0x3f, 0xfd, 0x80,
        0xb3, 0x42, 0xbd, 0x16, 0xe6, 0xdb, 0x7a, 0xa6, 0x03, 0x91, 0x0e, 0x13,
        0x36, 0x1a, 0x9b, 0xa5, 0xba, 0xf0, 0x4d, 0xf7, 0xf9, 0xf6, 0x26, 0xc2,
        0x7f, 0x3e, 0x71, 0xa7, 0x8e, 0x34, 0x3e, 0xf0, 0xdb, 0xfe, 0x21, 0x8b,
        0x85, 0x65, 0x3e, 0x77, 0x64, 0x9a, 0x9b, 0x57, 0x36, 0xc0, 0xb6, 0x62,
        0xad, 0x61, 0x49, 0x4c, 0x37, 0x4f, 0x2a, 0x38, 0x85, 0x11, 0x7f, 0x70,
        0x64, 0x6b, 0x13, 0xb6, 0x95, 0x86, 0xdd, 0x3f, 0xa4, 0xbd, 0x41, 0xb1,
        0xe2, 0x95, 0x8a, 0x9d, 0xe4, 0x11, 0xcf, 0xe5, 0x06, 0xd4, 0x7e, 0x62,
        0x2f, 0xc2, 0xcb, 0x59, 0x1f, 0xa7, 0xdd, 0xe0,
    ];
    let parsed =
        Ieee80211AuthFrame::parse_sae(&raw).expect("parse captured SAE frame");
    assert_eq!(&parsed.to_bytes(), &raw);
    assert_eq!([0x02, 0x00, 0x00, 0x00, 0x00, 0x00], parsed.da);
    assert_eq!([0x02, 0x00, 0x00, 0x00, 0x01, 0x00], parsed.sa);
    assert_eq!([0x02, 0x00, 0x00, 0x00, 0x01, 0x00], parsed.bssid);
    assert_eq!([0x02, 0x00, 0x00, 0x00, 0x00, 0x00], parsed.sta_mac());
    assert_eq!(0x013A, parsed.duration);
    assert_eq!(0x00E0, parsed.seq_ctrl);
    assert_eq!(1, parsed.transaction);
    assert_eq!(Ieee80211StatusCode::Success, parsed.status_code);
    assert_eq!(98, parsed.body().len());
    assert_eq!(&[0x13, 0x00], &parsed.body()[0..2]);
}
