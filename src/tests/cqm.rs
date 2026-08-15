// SPDX-License-Identifier: MIT

// Round-trip tests for the connection quality monitor attributes
// (`NL80211_ATTR_CQM` and its nested sub-attributes), the
// `NL80211_CMD_SET_CQM` request builder and the `NL80211_CMD_NOTIFY_CQM`
// event.
//
// The `test_captured_*` blobs are full netlink messages captured on the
// `nl0` nlmon netlink monitor (LINKTYPE_NETLINK) while shulid connected
// to a mac80211_hwsim hostapd AP and armed the kernel connection quality
// monitor; the `NL80211_ATTR_WIPHY`/`NL80211_ATTR_IFINDEX` values and the
// dynamic nl80211 family id (0x2c) are those of the capture. The other
// blobs are hand-built netlink attributes (length, type, value) padded to
// the 4-byte netlink alignment, mirroring the kernel's `nla_put` wire
// format.

use genetlink::message::RawGenlMessage;
use netlink_packet_core::{
    Emitable, NetlinkMessage, NetlinkPayload, NlaBuffer, Parseable,
};
use netlink_packet_generic::GenlMessage;

use crate::{
    Nl80211Attr, Nl80211Command, Nl80211Cqm, Nl80211CqmAttr,
    Nl80211CqmRssiThresholdEvent, Nl80211Event, Nl80211Message,
};

fn assert_roundtrip(expected: Nl80211Attr, raw: Vec<u8>) {
    assert_eq!(
        expected,
        Nl80211Attr::parse(&NlaBuffer::new_checked(&raw).unwrap()).unwrap()
    );
    let mut buf = vec![0; expected.buffer_len()];
    expected.emit(&mut buf);
    assert_eq!(buf, raw);
}

// NL80211_ATTR_CQM (94), a nested attribute holding
// NL80211_ATTR_CQM_RSSI_THOLD (1, s32) and NL80211_ATTR_CQM_RSSI_HYST
// (2, u32).
#[test]
fn test_cqm_threshold_roundtrip() {
    // Outer attribute: 4-byte header + 16-byte payload (two 8-byte
    // sub-attributes: RSSI_THOLD=-70 (0xffffffba), RSSI_HYST=5).
    let raw = vec![
        0x14, 0x00, 0x5e, 0x80, 0x08, 0x00, 0x01, 0x00, 0xba, 0xff, 0xff, 0xff,
        0x08, 0x00, 0x02, 0x00, 0x05, 0x00, 0x00, 0x00,
    ];
    assert_roundtrip(
        Nl80211Attr::Cqm(vec![
            Nl80211CqmAttr::RssiThold(-70),
            Nl80211CqmAttr::RssiHyst(5),
        ]),
        raw,
    );
}

// NL80211_ATTR_CQM (94) as carried by a `NL80211_CMD_NOTIFY_CQM` event:
// NL80211_ATTR_CQM_RSSI_THRESHOLD_EVENT (3, u32) + NL80211_ATTR_CQM_RSSI_LEVEL
// (9, s32).
#[test]
fn test_cqm_event_roundtrip() {
    // Nested payload: THRESHOLD_EVENT=LOW (0), RSSI_LEVEL=-72 (0xffffffb8).
    let raw = vec![
        0x14, 0x00, 0x5e, 0x80, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x09, 0x00, 0xb8, 0xff, 0xff, 0xff,
    ];
    assert_roundtrip(
        Nl80211Attr::Cqm(vec![
            Nl80211CqmAttr::RssiThresholdEvent(
                Nl80211CqmRssiThresholdEvent::Low,
            ),
            Nl80211CqmAttr::RssiLevel(-72),
        ]),
        raw,
    );
}

// The SET_CQM request builder must attach the CQM attribute to the
// interface.
#[test]
fn test_cqm_request_builder() {
    let attrs = Nl80211Cqm::new(7).rssi_thold(-70).rssi_hyst(5).build();
    assert_eq!(
        attrs,
        vec![
            Nl80211Attr::IfIndex(7),
            Nl80211Attr::Cqm(vec![
                Nl80211CqmAttr::RssiThold(-70),
                Nl80211CqmAttr::RssiHyst(5),
            ]),
        ]
    );
}

// `NL80211_CMD_SET_CQM` (63) request captured on the `nl0` nlmon netlink
// monitor while shulid connected to a mac80211_hwsim hostapd AP (fixed
// -30 dBm signal) and armed the connection quality monitor at
// -10 dBm / 5 dBm hysteresis: nl80211 family id 0x2c, ifindex 574.
// Deserialize the full message and verify the command + attributes; the
// builder must reproduce exactly the captured attribute bytes.
#[test]
fn test_captured_set_cqm_message() {
    let raw = vec![
        0x30, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x05, 0x00, 0x10, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x3f, 0x01, 0x00, 0x00, 0x08, 0x00, 0x03, 0x00,
        0x3e, 0x02, 0x00, 0x00, 0x14, 0x00, 0x5e, 0x80, 0x08, 0x00, 0x01, 0x00,
        0xf6, 0xff, 0xff, 0xff, 0x08, 0x00, 0x02, 0x00, 0x05, 0x00, 0x00, 0x00,
    ];
    let msg = parse_request(&raw);
    assert_eq!(Nl80211Command::SetCqm, msg.cmd);
    assert_eq!(
        vec![
            Nl80211Attr::IfIndex(574),
            Nl80211Attr::Cqm(vec![
                Nl80211CqmAttr::RssiThold(-10),
                Nl80211CqmAttr::RssiHyst(5),
            ]),
        ],
        msg.attributes
    );
    let attributes = Nl80211Cqm::new(574).rssi_thold(-10).rssi_hyst(5).build();
    assert_eq!(&raw[20..], emit_attributes(attributes));
}

// `NL80211_CMD_NOTIFY_CQM` (64) event captured on the same run: the
// kernel reported the -30 dBm signal dropped below the -10 dBm roam
// threshold (LOW crossing, `NL80211_ATTR_CQM_RSSI_LEVEL` = -30). The
// event rides the `config` multicast group with the WIPHY (315) /
// IFINDEX (574) of the capture; the peer MAC is not included.
#[test]
fn test_captured_notify_cqm_event() {
    let raw = vec![
        0x38, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x08, 0x00, 0x01, 0x00,
        0x3b, 0x01, 0x00, 0x00, 0x08, 0x00, 0x03, 0x00, 0x3e, 0x02, 0x00, 0x00,
        0x14, 0x00, 0x5e, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x09, 0x00, 0xe2, 0xff, 0xff, 0xff,
    ];
    match parse_event(&raw).expect("parse event") {
        Nl80211Event::CqmRssi(ev) => {
            assert_eq!(315, ev.wiphy);
            assert_eq!(574, ev.if_index);
            assert_eq!(None, ev.mac);
            assert_eq!(
                vec![
                    Nl80211CqmAttr::RssiThresholdEvent(
                        Nl80211CqmRssiThresholdEvent::Low,
                    ),
                    Nl80211CqmAttr::RssiLevel(-30),
                ],
                ev.events
            );
        }
        other => panic!("unexpected event: {other:?}"),
    }
}

fn parse_request(raw: &[u8]) -> Nl80211Message {
    let msg = NetlinkMessage::<GenlMessage<Nl80211Message>>::deserialize(raw)
        .expect("deserialize SET_CQM request");
    match msg.payload {
        NetlinkPayload::InnerMessage(m) => m.payload,
        other => panic!("unexpected payload: {other:?}"),
    }
}

fn parse_event(raw: &[u8]) -> Option<Nl80211Event> {
    let msg =
        NetlinkMessage::<RawGenlMessage>::deserialize(raw).expect("event");
    Nl80211Event::parse(msg)
}

fn emit_attributes(attributes: Vec<Nl80211Attr>) -> Vec<u8> {
    let msg = Nl80211Message {
        cmd: Nl80211Command::SetCqm,
        attributes,
    };
    let mut buf = vec![0u8; msg.buffer_len()];
    msg.emit(&mut buf);
    buf
}
