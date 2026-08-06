// SPDX-License-Identifier: MIT

// On-wire `NL80211_CMD_CONTROL_PORT_FRAME` request transmitted by
// wpa_supplicant (EAPOL-Key message 2 of the WPA2-PSK 4-way handshake),
// captured on the `nl0` nlmon monitor against hostapd on mac80211_hwsim.
// The emitted attribute region must byte-match the captured message.

use netlink_packet_core::{EthernetProtocol, Nla, NlasIterator, Parseable};

use crate::{Nl80211Attr, Nl80211ControlPortFrame};

fn parse_message_attributes(raw: &[u8]) -> Vec<Nl80211Attr> {
    NlasIterator::new(raw)
        .map(|nla| Nl80211Attr::parse(&nla.unwrap()).unwrap())
        .collect()
}

#[test]
fn test_captured_control_port_frame_request() {
    // nlmsghdr(16) + genl header(4), attributes start at offset 20.
    let raw = vec![
        0xb4, 0x00, 0x00, 0x00, 0x32, 0x00, 0x05, 0x00, 0xc8, 0x75, 0x8e, 0x95,
        0xa7, 0x9b, 0xc0, 0xf4, 0x81, 0x00, 0x00, 0x00, 0x08, 0x00, 0x03, 0x00,
        0xd0, 0x01, 0x00, 0x00, 0x06, 0x00, 0x66, 0x00, 0x8e, 0x88, 0x00, 0x00,
        0x0a, 0x00, 0x06, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x7d, 0x00, 0x33, 0x00, 0x01, 0x03, 0x00, 0x75, 0x02, 0x01, 0x0a, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x19, 0x73, 0x9a,
        0xfe, 0xc8, 0x2b, 0x7c, 0x06, 0xac, 0xbc, 0x58, 0x3b, 0xb9, 0xcc, 0xd1,
        0xaa, 0xca, 0x68, 0x46, 0x69, 0xf0, 0x70, 0x18, 0xbc, 0xb5, 0x48, 0xfc,
        0x40, 0x11, 0x72, 0x16, 0x91, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x21, 0x59, 0x96, 0xb6, 0xf7, 0xf9, 0xae, 0xd2, 0x89, 0x90, 0x61,
        0xf5, 0xd5, 0xb9, 0x9e, 0xe2, 0x00, 0x16, 0x30, 0x14, 0x01, 0x00, 0x00,
        0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00,
        0x0f, 0xac, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x67, 0x00,
    ];
    assert_eq!(180, raw.len());
    let mut captured = parse_message_attributes(&raw[20..]);
    captured.sort_by_key(|attr| attr.kind());

    // The EAPOL-Key M2 body carries the WPA2-PSK RSNE.
    let frame = captured
        .iter()
        .find_map(|attr| {
            if let Nl80211Attr::Frame(frame) = attr {
                Some(frame.clone())
            } else {
                None
            }
        })
        .unwrap();
    assert_eq!(121, frame.len());
    // EAPOL header: version 1, type 3 (EAPOL-Key), length 0x75.
    assert_eq!(&frame[0..4], &[0x01, 0x03, 0x00, 0x75]);
    // EAPOL-Key descriptor type 2 (RSN).
    assert_eq!(0x02, frame[4]);
    // WPA2-PSK RSNE (element 48, len 0x14) inside the EAPOL body.
    assert!(frame.windows(2).any(|w| w == [0x30, 0x14]));

    let mut built = Nl80211ControlPortFrame::new(464)
        .mac([0x02, 0x00, 0x00, 0x00, 0x01, 0x00])
        .frame(frame)
        .control_port_ethertype(EthernetProtocol::Pae)
        .control_port_no_encrypt(true)
        .build();
    built.sort_by_key(|attr| attr.kind());
    assert_eq!(captured, built);
}

// Regression: `NL80211_ATTR_CONTROL_PORT_ETHERTYPE` (102 / 0x66) is
// dual-purpose. On connect/associate it carries a u16 ethertype, but in wiphy
// information the kernel emits it ZERO-LENGTH as a flag meaning "protocols
// other than PAE are supported" (nl80211.h). Parsing the flag form as a u16
// fails, and because attribute parsing is fail-fast a single flag makes an
// entire NL80211_CMD_GET_WIPHY dump unreadable.
//
// Attribute region from a real GET_WIPHY dump: Intel AX211 (iwlwifi) on
// Linux 7.0.0-22-generic. `04 00 66 00` is nla_len=4 (header only, no payload),
// nla_type=102.
#[test]
fn test_control_port_ethertype_zero_length_flag_in_wiphy() {
    let raw = vec![
        0x08, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, // Wiphy(1)
        0x04, 0x00, 0x66,
        0x00, // CONTROL_PORT_ETHERTYPE, zero-length flag
        0x08, 0x00, 0x71, 0x00, 0x03, 0x00, 0x00,
        0x00, // WiphyAntennaAvailTx(3)
    ];
    let attrs = parse_message_attributes(&raw);
    assert_eq!(
        vec![
            Nl80211Attr::Wiphy(1),
            Nl80211Attr::ControlPortEthertypeSupported,
            Nl80211Attr::WiphyAntennaAvailTx(3),
        ],
        attrs
    );
}

// The u16 form still parses, and both forms carry the same attribute id with
// the lengths the kernel expects.
#[test]
fn test_control_port_ethertype_both_forms() {
    let value = Nl80211Attr::ControlPortEthertype(EthernetProtocol::Pae);
    let flag = Nl80211Attr::ControlPortEthertypeSupported;

    assert_eq!(value.kind(), flag.kind());
    assert_eq!(2, value.value_len());
    assert_eq!(0, flag.value_len());

    // The u16 form round-trips through a 2-byte payload.
    let raw = vec![0x06, 0x00, 0x66, 0x00, 0x8e, 0x88, 0x00, 0x00];
    assert_eq!(vec![value], parse_message_attributes(&raw));
}
