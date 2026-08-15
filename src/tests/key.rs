// SPDX-License-Identifier: MIT

// On-wire `NL80211_ATTR_*` bytes captured on an `nlmon` netlink monitor while
// wpa_supplicant connected to a WPA3-Personal AP (hostapd + mac80211_hwsim).
// Each `raw` blob is a single netlink attribute (length, type, value), padded
// to the 4-byte netlink alignment, taken from the `NL80211_CMD_AUTHENTICATE`,
// `NL80211_CMD_ASSOCIATE` and `NL80211_CMD_NEW_KEY` messages. They validate our
// parsing and emitting against exactly what wpa_supplicant and the kernel
// exchange.

use netlink_packet_core::{
    Emitable, EthernetProtocol, NlaBuffer, NlasIterator, Parseable,
};

use crate::{
    Ieee80211CipherSuite, Nl80211Attr, Nl80211Command, Nl80211Key,
    Nl80211KeyAttr, Nl80211KeyDefaultType, Nl80211KeyType, Nl80211Message,
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

// NL80211_ATTR_AUTH_DATA from CMD_AUTHENTICATE: the SAE commit (transaction 1,
// status 0, group 19, then commit-scalar and commit-element).
#[test]
fn test_captured_auth_data_commit() {
    let raw = vec![
        0x6a, 0x00, 0x9c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x13, 0x00, 0xe6, 0x80,
        0xd7, 0x0e, 0x07, 0xb8, 0x07, 0x82, 0x2f, 0xd1, 0x20, 0x51, 0x27, 0xcc,
        0x09, 0xbb, 0x85, 0x40, 0xdc, 0x5a, 0x24, 0xd7, 0x07, 0xdb, 0x93, 0xf8,
        0x3e, 0x65, 0x37, 0xc5, 0x2b, 0xb8, 0xc0, 0x2b, 0x8b, 0x26, 0x52, 0x19,
        0x68, 0x84, 0xa9, 0x5b, 0x16, 0x7e, 0xcd, 0x6d, 0x0b, 0xfb, 0xbb, 0x20,
        0x20, 0x15, 0x3f, 0x59, 0xce, 0xa1, 0x0b, 0x77, 0x69, 0xf6, 0x88, 0x2d,
        0x6f, 0x83, 0x5e, 0x11, 0xaf, 0xeb, 0x7c, 0x7f, 0xa6, 0x79, 0x20, 0xcb,
        0x7e, 0xf1, 0x38, 0x08, 0x19, 0x0b, 0x41, 0xb0, 0xcb, 0xe5, 0x2b, 0x6e,
        0x98, 0x01, 0xfd, 0x0a, 0x73, 0x29, 0x93, 0x6f, 0x0d, 0x2d, 0x00, 0x00,
    ];
    let len = u16::from_le_bytes([raw[0], raw[1]]) as usize;
    assert_roundtrip(Nl80211Attr::AuthData(raw[4..len].to_vec()), raw);
}

// NL80211_ATTR_AUTH_DATA from CMD_AUTHENTICATE: the SAE confirm (transaction 2,
// status 0, send-confirm 1, then the 32-byte confirm hash).
#[test]
fn test_captured_auth_data_confirm() {
    let raw = vec![
        0x2a, 0x00, 0x9c, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0xfe, 0x76,
        0x6d, 0xff, 0xb8, 0xdb, 0xa8, 0x4f, 0x9b, 0x7f, 0x8d, 0xdd, 0x44, 0xbf,
        0xfa, 0x85, 0xff, 0x31, 0x49, 0x28, 0xa0, 0x6c, 0x35, 0x82, 0x9f, 0x50,
        0xf5, 0xa7, 0x53, 0x67, 0x3b, 0x46, 0x00, 0x00,
    ];
    let len = u16::from_le_bytes([raw[0], raw[1]]) as usize;
    assert_roundtrip(Nl80211Attr::AuthData(raw[4..len].to_vec()), raw);
}

// NL80211_ATTR_CONTROL_PORT_ETHERTYPE from CMD_ASSOCIATE: ETH_P_PAE (0x888E).
#[test]
fn test_captured_control_port_ethertype() {
    let raw = vec![0x06, 0x00, 0x66, 0x00, 0x8e, 0x88, 0x00, 0x00];
    assert_roundtrip(
        Nl80211Attr::ControlPortEthertype(EthernetProtocol::from(0x888E)),
        raw,
    );
}

// Nested NL80211_ATTR_KEY from CMD_NEW_KEY installing the pairwise (CCMP-128)
// key: KEY_DATA, KEY_CIPHER (00-0f-ac:4), KEY_SEQ, KEY_IDX (0). Captured
// via nlmon while wpa_supplicant connected to a WPA3-SAE AP (hostapd +
// mac80211_hwsim).
#[test]
fn test_captured_new_key_pairwise() {
    let raw = vec![
        0x34, 0x00, 0x50, 0x00, // len=52, type=80 (NL80211_ATTR_KEY)
        0x14, 0x00, 0x01, 0x00, // KEY_DATA, len 20
        0x8d, 0x44, 0x6e, 0x9e, 0xe5, 0x83, 0xa3, 0x0c, 0xfb, 0x25, 0xee, 0xa7,
        0xf4, 0x1b, 0x26, 0x3d, 0x08, 0x00, 0x03, 0x00, // KEY_CIPHER
        0x04, 0xac, 0x0f, 0x00, 0x0a, 0x00, 0x04, 0x00, // KEY_SEQ, len 10
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 6B + 2B pad
        0x05, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, // KEY_IDX = 0
    ];
    let expected = Nl80211Attr::Key(vec![
        Nl80211KeyAttr::Data(vec![
            0x8d, 0x44, 0x6e, 0x9e, 0xe5, 0x83, 0xa3, 0x0c, 0xfb, 0x25, 0xee,
            0xa7, 0xf4, 0x1b, 0x26, 0x3d,
        ]),
        Nl80211KeyAttr::Cipher(0x000F_AC04),
        Nl80211KeyAttr::Seq(vec![0u8; 6]),
        Nl80211KeyAttr::Idx(0),
    ]);
    assert_roundtrip(expected, raw);
}

// Nested NL80211_ATTR_KEY from CMD_NEW_KEY installing the group (CCMP-128)
// key at index 1. Captured via nlmon while wpa_supplicant connected to a
// WPA3-SAE AP (hostapd + mac80211_hwsim).
#[test]
fn test_captured_new_key_group() {
    let raw = vec![
        0x34, 0x00, 0x50, 0x00, // len=52, type=80 (NL80211_ATTR_KEY)
        0x14, 0x00, 0x01, 0x00, // KEY_DATA, len 20
        0x74, 0xf3, 0xcc, 0xf7, 0x16, 0x8a, 0xfe, 0x9a, 0xaa, 0x26, 0x08, 0xd4,
        0xe8, 0xc1, 0xca, 0x95, 0x08, 0x00, 0x03, 0x00, // KEY_CIPHER
        0x04, 0xac, 0x0f, 0x00, 0x0a, 0x00, 0x04, 0x00, // KEY_SEQ, len 10
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 6B + 2B pad
        0x05, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, // KEY_IDX = 1
    ];
    let expected = Nl80211Attr::Key(vec![
        Nl80211KeyAttr::Data(vec![
            0x74, 0xf3, 0xcc, 0xf7, 0x16, 0x8a, 0xfe, 0x9a, 0xaa, 0x26, 0x08,
            0xd4, 0xe8, 0xc1, 0xca, 0x95,
        ]),
        Nl80211KeyAttr::Cipher(0x000F_AC04),
        Nl80211KeyAttr::Seq(vec![0u8; 6]),
        Nl80211KeyAttr::Idx(1),
    ]);
    assert_roundtrip(expected, raw);
}

// Nested NL80211_ATTR_KEY from CMD_SET_KEY marking the group key at index 1
// as the default multicast key: KEY_IDX (1), KEY_DEFAULT, KEY_DEFAULT_TYPES
// nested with NL80211_KEY_DEFAULT_TYPE_MULTICAST.
//
// Captured via nlmon while shulid sent SET_KEY after NEW_KEY (matching
// wpa_supplicant's documented pattern at src/drivers/driver_nl80211.c:3624
// which is used for IBSS / other modes requiring DEFAULT flag).  Wire bytes
// verified with `tshark -r traffic.pcap -x`.
#[test]
fn test_captured_set_key_group_default_types() {
    let raw = vec![
        0x18, 0x00, 0x50, 0x00, // len=24, type=80 (NL80211_ATTR_KEY)
        0x05, 0x00, 0x02, 0x00, // KEY_IDX: len=5, type=2
        0x01, 0x00, 0x00, 0x00, // value=1 + pad
        0x04, 0x00, 0x05, 0x00, // KEY_DEFAULT: len=4, type=5 (flag)
        0x08, 0x00, 0x08,
        0x00, // KEY_DEFAULT_TYPES: len=8, type=8 (nested)
        0x04, 0x00, 0x02, 0x00, //   MULTICAST flag: len=4, type=2
    ];
    let expected = Nl80211Attr::Key(vec![
        Nl80211KeyAttr::Idx(1),
        Nl80211KeyAttr::Default,
        Nl80211KeyAttr::DefaultTypes(vec![Nl80211KeyDefaultType::Multicast]),
    ]);
    assert_roundtrip(expected, raw);
}

// Full `NL80211_CMD_NEW_KEY` request messages (WPA2-PSK "Test-WIFI", AP
// BSSID 02:00:00:00:01:00, ifindex 464), captured on the `nl0` nlmon
// monitor while wpa_supplicant connected. The emitted attribute region must
// byte-match the captured message exactly.

fn emit_new_key_attributes(attributes: Vec<Nl80211Attr>) -> Vec<u8> {
    let msg = Nl80211Message {
        cmd: Nl80211Command::NewKey,
        attributes,
    };
    let mut buf = vec![0u8; msg.buffer_len()];
    msg.emit(&mut buf);
    buf
}

fn parse_message_attributes(raw: &[u8]) -> Vec<Nl80211Attr> {
    NlasIterator::new(raw)
        .map(|nla| Nl80211Attr::parse(&nla.unwrap()).unwrap())
        .collect()
}

// Installing the pairwise (CCMP-128) key: NL80211_ATTR_IFINDEX,
// NL80211_ATTR_MAC, then NL80211_ATTR_KEY with KEY_DATA, KEY_CIPHER
// (00-0f-ac:4), KEY_SEQ (6-byte RSC) and KEY_IDX (0).
#[test]
fn test_captured_new_key_message_pairwise() {
    // nlmsghdr(16) + genl header(4), attributes start at offset 20.
    let raw = vec![
        0x5c, 0x00, 0x00, 0x00, 0x32, 0x00, 0x05, 0x00, 0xca, 0x75, 0x8e, 0x95,
        0xa7, 0x9b, 0xc0, 0xf4, 0x0b, 0x00, 0x00, 0x00, 0x08, 0x00, 0x03, 0x00,
        0xd0, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x06, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x34, 0x00, 0x50, 0x00, 0x14, 0x00, 0x01, 0x00,
        0x7d, 0x94, 0x07, 0x6d, 0x81, 0x6d, 0x04, 0x86, 0xbf, 0x22, 0x80, 0xa9,
        0x56, 0xa7, 0xe6, 0x51, 0x08, 0x00, 0x03, 0x00, 0x04, 0xac, 0x0f, 0x00,
        0x0a, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(92, raw.len());
    let attributes = Nl80211Key::new(464)
        .mac([0x02, 0x00, 0x00, 0x00, 0x01, 0x00])
        .key_data(vec![
            0x7d, 0x94, 0x07, 0x6d, 0x81, 0x6d, 0x04, 0x86, 0xbf, 0x22, 0x80,
            0xa9, 0x56, 0xa7, 0xe6, 0x51,
        ])
        .key_index(0)
        .cipher(Ieee80211CipherSuite::Ccmp128)
        .seq(vec![0u8; 6])
        .build();
    assert_eq!(&raw[20..], emit_new_key_attributes(attributes));
}

// Installing the group key (CCMP-128) at index 1: same shape but no
// NL80211_ATTR_MAC and KEY_IDX (1).
#[test]
fn test_captured_new_key_message_group() {
    let raw = vec![
        0x50, 0x00, 0x00, 0x00, 0x32, 0x00, 0x05, 0x00, 0xcb, 0x75, 0x8e, 0x95,
        0xa7, 0x9b, 0xc0, 0xf4, 0x0b, 0x00, 0x00, 0x00, 0x08, 0x00, 0x03, 0x00,
        0xd0, 0x01, 0x00, 0x00, 0x34, 0x00, 0x50, 0x00, 0x14, 0x00, 0x01, 0x00,
        0xb6, 0x29, 0xc4, 0x84, 0x95, 0x0e, 0x72, 0x3e, 0x1e, 0xfc, 0xe5, 0x31,
        0x1e, 0x68, 0x2d, 0xf8, 0x08, 0x00, 0x03, 0x00, 0x04, 0xac, 0x0f, 0x00,
        0x0a, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00,
    ];
    assert_eq!(80, raw.len());
    let attributes = Nl80211Key::new(464)
        .key_data(vec![
            0xb6, 0x29, 0xc4, 0x84, 0x95, 0x0e, 0x72, 0x3e, 0x1e, 0xfc, 0xe5,
            0x31, 0x1e, 0x68, 0x2d, 0xf8,
        ])
        .key_index(1)
        .cipher(Ieee80211CipherSuite::Ccmp128)
        .seq(vec![0u8; 6])
        .build();
    assert_eq!(&raw[20..], emit_new_key_attributes(attributes));
}

// The convenience constructors add what wpa_supplicant leaves off the wire:
// NL80211_KEY_TYPE, and for the GTK the default-multicast
// NL80211_KEY_DEFAULT_TYPES (the SET_KEY form of which is validated against
// a capture above).
#[test]
fn test_new_key_conveniences() {
    let ptk = emit_new_key_attributes(
        Nl80211Key::new_ptk(
            464,
            [0x02, 0x00, 0x00, 0x00, 0x01, 0x00],
            vec![0xaa; 16],
        )
        .build(),
    );
    assert_eq!(
        vec![
            Nl80211Attr::IfIndex(464),
            Nl80211Attr::Mac([0x02, 0x00, 0x00, 0x00, 0x01, 0x00]),
            Nl80211Attr::Key(vec![
                Nl80211KeyAttr::Data(vec![0xaa; 16]),
                Nl80211KeyAttr::Cipher(0x000F_AC04),
                Nl80211KeyAttr::Idx(0),
                Nl80211KeyAttr::Type(Nl80211KeyType::Pairwise),
            ]),
        ],
        parse_message_attributes(&ptk)
    );

    let gtk = emit_new_key_attributes(
        Nl80211Key::new_gtk(464, vec![0xbb; 16], 1).build(),
    );
    assert_eq!(
        vec![
            Nl80211Attr::IfIndex(464),
            Nl80211Attr::Key(vec![
                Nl80211KeyAttr::Data(vec![0xbb; 16]),
                Nl80211KeyAttr::Cipher(0x000F_AC04),
                Nl80211KeyAttr::Idx(1),
                Nl80211KeyAttr::Type(Nl80211KeyType::Group),
                Nl80211KeyAttr::DefaultTypes(vec![
                    Nl80211KeyDefaultType::Multicast
                ]),
            ]),
        ],
        parse_message_attributes(&gtk)
    );
}

// The IGTK convenience installs BIP-CMAC-128 (00-0f-ac:6) at the AP-assigned
// index (4-5) with the IPN as KEY_SEQ and the NL80211_KEY_DEFAULT_MGMT flag.
#[test]
fn test_new_key_igtk_convenience() {
    let igtk = emit_new_key_attributes(
        Nl80211Key::new_igtk(464, vec![0xcc; 16], 4, vec![0x01; 6]).build(),
    );
    assert_eq!(
        vec![
            Nl80211Attr::IfIndex(464),
            Nl80211Attr::Key(vec![
                Nl80211KeyAttr::Data(vec![0xcc; 16]),
                Nl80211KeyAttr::Cipher(0x000F_AC06),
                Nl80211KeyAttr::Seq(vec![0x01; 6]),
                Nl80211KeyAttr::Idx(4),
                Nl80211KeyAttr::Type(Nl80211KeyType::Group),
                Nl80211KeyAttr::DefaultMgmt,
            ]),
        ],
        parse_message_attributes(&igtk)
    );
}

// The BIGTK convenience installs BIP-CMAC-128 at index 6-7 without the
// default-management flag (beacon protection is RX-only).
#[test]
fn test_new_key_bigtk_convenience() {
    let bigtk = emit_new_key_attributes(
        Nl80211Key::new_bigtk(464, vec![0xdd; 16], 6, vec![0x02; 6]).build(),
    );
    assert_eq!(
        vec![
            Nl80211Attr::IfIndex(464),
            Nl80211Attr::Key(vec![
                Nl80211KeyAttr::Data(vec![0xdd; 16]),
                Nl80211KeyAttr::Cipher(0x000F_AC06),
                Nl80211KeyAttr::Seq(vec![0x02; 6]),
                Nl80211KeyAttr::Idx(6),
                Nl80211KeyAttr::Type(Nl80211KeyType::Group),
            ]),
        ],
        parse_message_attributes(&bigtk)
    );
}
