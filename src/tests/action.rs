// SPDX-License-Identifier: MIT

use crate::{
    Ieee80211ActionFrame, Ieee80211AuthFrameSae, Ieee80211BtmRequest,
    Ieee80211BtmResponse, Ieee80211Frame, Ieee80211NeighborReportRequest,
    Ieee80211NeighborReportResponse, Ieee80211StatusCode,
};

fn btm_request_body(dialog_token: u8) -> Vec<u8> {
    let mut body = vec![
        dialog_token,
        0x01, // preferred candidate list included
        0x00,
        0x00, // disassociation timer
        0x14, // validity interval
    ];
    body.extend_from_slice(&[52, 14]); // Neighbor Report element
    body.extend_from_slice(&[0x02, 0, 0, 0, 1, 0]); // BSSID
    body.extend_from_slice(&[13, 0, 0, 0]); // BSSID info
    body.extend_from_slice(&[81, 6, 10, 255]); // op class, ch, PHY, pref
    body
}

#[test]
fn action_frame_other_roundtrip() {
    let sta = [0x02u8; 6];
    let ap = [0x01u8; 6];
    let body = b"action body".to_vec();
    let raw =
        Ieee80211ActionFrame::new(sta, ap, 0x7e, 0x01, body.clone()).to_bytes();

    let parsed = Ieee80211ActionFrame::parse(&raw).expect("parse action frame");
    let Ieee80211ActionFrame::Other(frame) = &parsed else {
        panic!("unexpected variant: {parsed:?}");
    };
    assert_eq!(frame.frame_control, Ieee80211ActionFrame::FRAME_TYPE);
    assert_eq!(frame.duration, 0);
    assert_eq!(frame.da, ap);
    assert_eq!(frame.sa, sta);
    assert_eq!(frame.bssid, ap);
    assert_eq!(frame.seq_ctrl, 0);
    assert_eq!(frame.category, 0x7e);
    assert_eq!(frame.action, 0x01);
    assert_eq!(frame.body(), body.as_slice());
    assert_eq!(frame.sta_mac(), sta);
    assert_eq!(parsed.to_bytes(), raw);
}

#[test]
fn action_frame_accepts_empty_body() {
    let raw = Ieee80211ActionFrame::new(
        [0x02u8; 6],
        [0x01u8; 6],
        0x7e,
        0x01,
        Vec::new(),
    )
    .to_bytes();
    assert_eq!(raw.len(), 26);

    let parsed = Ieee80211ActionFrame::parse(&raw).expect("parse action frame");
    assert!(parsed.body().is_empty());
}

#[test]
fn action_frame_parse_rejects_short_frame() {
    let mut raw = Ieee80211ActionFrame::new(
        [0x02u8; 6],
        [0x01u8; 6],
        0x7e,
        0x01,
        Vec::new(),
    )
    .to_bytes();
    raw.pop();
    assert!(Ieee80211ActionFrame::parse(&raw).is_err());
}

#[test]
fn action_frame_parse_rejects_other_subtypes() {
    let auth = Ieee80211AuthFrameSae::new(
        [0x02u8; 6],
        [0x01u8; 6],
        1,
        Ieee80211StatusCode::Success,
        vec![0; 16],
    )
    .to_bytes();
    assert!(Ieee80211ActionFrame::parse(&auth).is_err());
}

#[test]
fn parse_wnm_btm_request() {
    let sta = [0x02u8; 6];
    let ap = [0x01u8; 6];
    let mut frame = Ieee80211ActionFrame::new(
        ap,
        ap,
        Ieee80211BtmRequest::CATEGORY,
        Ieee80211BtmRequest::ACTION,
        btm_request_body(7),
    );
    // A BTM Request travels AP -> STA.
    if let Ieee80211ActionFrame::Other(other) = &mut frame {
        other.da = sta;
        other.sa = ap;
    }
    let raw = frame.to_bytes();

    let parsed = Ieee80211ActionFrame::parse(&raw).expect("parse BTM request");
    assert!(parsed.is_btm_request());
    assert!(!parsed.is_btm_response());
    assert_eq!(parsed.category(), Ieee80211BtmRequest::CATEGORY);
    assert_eq!(parsed.action(), Ieee80211BtmRequest::ACTION);
    let btm = parsed.btm_request().expect("decode BTM request");
    assert_eq!(btm.sta_mac(), sta);
    assert_eq!(btm.request.dialog_token, 7);
    assert!(btm.request.preferred_candidates);
    assert_eq!(btm.request.candidates.len(), 1);
    let candidate = &btm.request.candidates[0];
    assert_eq!(candidate.bssid, [0x02, 0, 0, 0, 1, 0]);
    assert_eq!(candidate.bssid_info, 13);
    assert_eq!(candidate.preference, Some(255));
}

#[test]
fn build_wnm_btm_response() {
    let sta = [0x02u8; 6];
    let ap = [0x01u8; 6];
    let target = [0x02, 0, 0, 0, 2, 0];
    let response = Ieee80211BtmResponse::new(
        7,
        Ieee80211BtmResponse::STATUS_ACCEPT,
        target,
    );
    let expected_body = response.build();
    let raw = Ieee80211ActionFrame::new_btm_response(sta, ap, response.clone())
        .to_bytes();

    let parsed = Ieee80211ActionFrame::parse(&raw).expect("parse BTM response");
    assert!(parsed.is_btm_response());
    assert!(!parsed.is_btm_request());
    let btm = parsed.btm_response().expect("decode BTM response");
    assert_eq!(btm.sta_mac(), sta);
    assert_eq!(btm.da, ap);
    assert_eq!(btm.sa, sta);
    assert_eq!(btm.body(), &expected_body[2..]);
    assert_eq!(btm.response, response);
}

#[test]
fn parse_rrm_neighbor_report_response() {
    let sta = [0x02u8; 6];
    let ap = [0x01u8; 6];
    let mut body = vec![0x2a];
    body.extend_from_slice(&[52, 13]); // Neighbor Report element
    body.extend_from_slice(&[0x02, 0, 0, 0, 3, 0]); // BSSID
    body.extend_from_slice(&[1, 0, 0, 0]); // BSSID info
    body.extend_from_slice(&[81, 6, 7]); // op class, channel, PHY
    body.extend_from_slice(&[6, 3, 1, 2, 3]); // optional subelement

    let mut frame = Ieee80211ActionFrame::new(
        ap,
        ap,
        Ieee80211NeighborReportResponse::CATEGORY,
        Ieee80211NeighborReportResponse::ACTION,
        body,
    );
    // A Neighbor Report Response travels AP -> STA.
    if let Ieee80211ActionFrame::Other(other) = &mut frame {
        other.da = sta;
        other.sa = ap;
    }
    let raw = frame.to_bytes();

    let parsed = Ieee80211ActionFrame::parse(&raw)
        .expect("parse neighbor report response");
    assert!(parsed.is_neighbor_report_response());
    assert!(!parsed.is_neighbor_report_request());
    assert_eq!(parsed.sta_mac(), sta);
    let response = parsed
        .neighbor_report_response()
        .expect("decode neighbor report response");
    assert_eq!(response.response.dialog_token, 0x2a);
    assert_eq!(response.response.entries.len(), 1);
    let entry = &response.response.entries[0];
    assert_eq!(entry.bssid, [0x02, 0, 0, 0, 3, 0]);
    assert_eq!(entry.operating_class, 81);
    assert_eq!(entry.channel, 6);
    assert_eq!(entry.phy_type, 7);
}

#[test]
fn build_rrm_neighbor_report_request() {
    let sta = [0x02u8; 6];
    let ap = [0x01u8; 6];
    let request = Ieee80211NeighborReportRequest::new(0x2a);
    let raw = Ieee80211ActionFrame::new_neighbor_report_request(
        sta,
        ap,
        request.clone(),
    )
    .to_bytes();

    let parsed = Ieee80211ActionFrame::parse(&raw)
        .expect("parse neighbor report request");
    assert!(parsed.is_neighbor_report_request());
    assert!(!parsed.is_neighbor_report_response());
    let frame = parsed
        .neighbor_report_request()
        .expect("decode neighbor report request");
    assert_eq!(frame.sta_mac(), sta);
    assert_eq!(frame.da, ap);
    assert_eq!(frame.body(), &[0x2a]);
    assert_eq!(frame.request, request);
}

#[test]
fn ieee80211_frame_dispatch() {
    let sta = [0x02u8; 6];
    let ap = [0x01u8; 6];

    let auth = Ieee80211AuthFrameSae::new(
        sta,
        ap,
        1,
        Ieee80211StatusCode::Success,
        vec![0; 16],
    )
    .to_bytes();
    assert!(matches!(
        Ieee80211Frame::parse(&auth).expect("parse auth"),
        Ieee80211Frame::Auth(_)
    ));

    let action = Ieee80211ActionFrame::new_neighbor_report_request(
        sta,
        ap,
        Ieee80211NeighborReportRequest::new(1),
    )
    .to_bytes();
    assert!(matches!(
        Ieee80211Frame::parse(&action).expect("parse action"),
        Ieee80211Frame::Action(_)
    ));

    // Probe Request subtype: no full-frame codec, kept as Other.
    assert!(matches!(
        Ieee80211Frame::parse(&[0x40, 0x00]).expect("parse other"),
        Ieee80211Frame::Other { .. }
    ));
}
