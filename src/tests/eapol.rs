// SPDX-License-Identifier: MIT

use crate::eapol::OFF_MIC;
use crate::{
    Ieee80211EapolEapFrame, Ieee80211EapolFrame, Ieee80211EapolKeyFrame,
};

#[test]
fn roundtrip_msg2() {
    let snonce = [0xABu8; 32];
    let rsne = vec![0x30, 0x14, 0x01, 0x00];
    let pdu = Ieee80211EapolKeyFrame::build_message_2(&snonce, 1, &rsne, 0);
    let parsed = Ieee80211EapolKeyFrame::parse(&pdu).unwrap();
    assert!(parsed.has_mic());
    assert!(parsed.is_pairwise());
    assert_eq!(parsed.key_nonce, snonce);
    assert_eq!(parsed.key_data, rsne);
    assert_eq!(parsed.replay_counter, 1);
}

#[test]
fn mic_offset_is_correct() {
    assert_eq!(OFF_MIC, 81);
    let pdu = Ieee80211EapolKeyFrame::build_message_4(&[0u8; 32], 2, 0);
    let zeroed = Ieee80211EapolKeyFrame::pdu_with_zeroed_mic(&pdu);
    assert_eq!(&zeroed[OFF_MIC..OFF_MIC + 16], &[0u8; 16]);
}

#[test]
fn reject_non_eapol() {
    assert!(Ieee80211EapolKeyFrame::parse(&[0u8; 20]).is_none());
}

#[test]
fn eap_frame_roundtrip() {
    let pdu = Ieee80211EapolEapFrame::build(b"hello");
    let parsed = Ieee80211EapolEapFrame::parse(&pdu).expect("parse EAP frame");
    assert_eq!(parsed.payload, b"hello");
    assert!(Ieee80211EapolEapFrame::parse(b"\x02\x03\x00\x00").is_none());
}

#[test]
fn eapol_frame_dispatch() {
    let key_pdu =
        Ieee80211EapolKeyFrame::build_message_2(&[0u8; 32], 1, &[], 0);
    assert!(matches!(
        Ieee80211EapolFrame::parse(&key_pdu),
        Ieee80211EapolFrame::Key(_)
    ));

    let eap_pdu = Ieee80211EapolEapFrame::build(b"hello");
    assert!(matches!(
        Ieee80211EapolFrame::parse(&eap_pdu),
        Ieee80211EapolFrame::Eap(_)
    ));

    assert!(matches!(
        Ieee80211EapolFrame::parse(&[2, 2, 0, 0]),
        Ieee80211EapolFrame::Other(_)
    ));
}
