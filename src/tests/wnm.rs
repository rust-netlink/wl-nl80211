// SPDX-License-Identifier: MIT

use crate::{Ieee80211BtmRequest, Ieee80211BtmResponse};

/// Build a BTM Request body: dialog token, request mode, disassociation
/// timer, validity interval, then Neighbor Report candidate elements.
/// Each candidate is (BSSID, BSSID info, op class, channel, phy type,
/// preference).
#[allow(clippy::type_complexity)]
fn btm_request_body(
    dialog_token: u8,
    req_mode: u8,
    candidates: &[([u8; 6], u32, u8, u8, u8, u8)],
) -> Vec<u8> {
    let mut body = vec![
        dialog_token,
        req_mode,
        0x00,
        0x00, // disassociation timer
        0x14, // validity interval
    ];
    for (bssid, info, op_class, channel, phy, preference) in candidates {
        body.push(52); // Neighbor Report element ID
        body.push(14); // length: 13 fixed + preference
        body.extend_from_slice(bssid);
        body.extend_from_slice(&info.to_le_bytes());
        body.push(*op_class);
        body.push(*channel);
        body.push(*phy);
        body.push(*preference);
    }
    body
}

#[test]
fn test_parse_btm_request_candidates() {
    let candidate_bssid = [0x02, 0x00, 0x00, 0x00, 0x01, 0x00];
    let body = btm_request_body(
        7,
        0x01, // preferred candidate list included
        &[(candidate_bssid, 0x0000_000d, 81, 6, 10, 255)],
    );
    let req = Ieee80211BtmRequest::parse(&body).expect("parse");
    assert_eq!(req.dialog_token, 7);
    assert!(req.preferred_candidates);
    assert_eq!(req.disassoc_timer, 0);
    assert_eq!(req.validity_interval, 0x14);
    assert_eq!(req.candidates.len(), 1);
    let candidate = &req.candidates[0];
    assert_eq!(candidate.bssid, candidate_bssid);
    assert_eq!(candidate.bssid_info, 0x0000_000d);
    assert_eq!(candidate.operating_class, 81);
    assert_eq!(candidate.channel, 6);
    assert_eq!(candidate.phy_type, 10);
    assert_eq!(candidate.preference, Some(255));
}

#[test]
fn test_parse_btm_request_no_candidates() {
    let body = vec![
        3, 0x06, // disassoc imminent + BSS termination flags
        0x0a, 0x00, // disassociation timer = 10
        0x05, // validity interval
    ];
    let req = Ieee80211BtmRequest::parse(&body).expect("parse");
    assert_eq!(req.dialog_token, 3);
    assert!(!req.preferred_candidates);
    assert_eq!(req.disassoc_timer, 10);
    assert!(req.candidates.is_empty());
}

#[test]
fn test_parse_btm_request_too_short() {
    assert!(Ieee80211BtmRequest::parse(&[1, 0]).is_none());
}

#[test]
fn test_build_btm_response() {
    let target = [0x02, 0x00, 0x00, 0x00, 0x02, 0x00];
    let frame = Ieee80211BtmResponse::new(
        7,
        Ieee80211BtmResponse::STATUS_ACCEPT,
        target,
    )
    .build();
    assert_eq!(frame[0], Ieee80211BtmResponse::CATEGORY);
    assert_eq!(frame[1], Ieee80211BtmResponse::ACTION);
    assert_eq!(frame[2], 7); // dialog token echoed
    assert_eq!(frame[3], Ieee80211BtmResponse::STATUS_ACCEPT);
    assert_eq!(frame[4], 0); // termination delay
    assert_eq!(&frame[5..11], target.as_slice());
}

#[test]
fn test_btm_action_numbers() {
    // Sanity: the action codes used on the wire (802.11-2020 Table
    // 9-459): 6 is the BTM Query, 7 the Request, 8 the Response.
    assert_eq!(Ieee80211BtmRequest::ACTION, 7);
    assert_eq!(Ieee80211BtmResponse::ACTION, 8);
    assert_eq!(Ieee80211BtmRequest::CATEGORY, 10);
}
