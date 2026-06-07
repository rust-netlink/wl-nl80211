// SPDX-License-Identifier: MIT

// On-wire `NL80211_ATTR_*` bytes captured on the `nl0` netlink monitor while
// associating to a WPA3-Personal AP (hostapd + mac80211_hwsim) driven by
// wpa_supplicant. Each `raw` blob is a single netlink attribute (length, type,
// value), padded to the netlink 4-byte alignment, taken from the
// `NL80211_CMD_AUTHENTICATE` / `NL80211_CMD_ASSOCIATE` messages. They validate
// our parsing and emitting against what the kernel and userspace exchange.

use netlink_packet_core::{Emitable, NlaBuffer, Parseable};

use crate::{
    Nl80211AkmSuite, Nl80211Attr, Nl80211AuthType, Nl80211CipherSuite,
    Nl80211Element, Nl80211ElementRsn, Nl80211Elements, Nl80211RsnCapbilities,
    Nl80211UseMfp, Nl80211WpaVersions,
};

// NL80211_ATTR_AUTH_TYPE = NL80211_AUTHTYPE_SAE (from CMD_AUTHENTICATE).
#[test]
fn test_captured_auth_type_sae() {
    let raw = vec![0x08, 0x00, 0x35, 0x00, 0x04, 0x00, 0x00, 0x00];
    let expected = Nl80211Attr::AuthType(Nl80211AuthType::Sae);
    assert_eq!(
        expected,
        Nl80211Attr::parse(&NlaBuffer::new_checked(&raw).unwrap()).unwrap()
    );
    let mut buf = vec![0; expected.buffer_len()];
    expected.emit(&mut buf);
    assert_eq!(buf, raw);
}

// NL80211_ATTR_WPA_VERSIONS = NL80211_WPA_VERSION_3.
#[test]
fn test_captured_wpa_versions() {
    let raw = vec![0x08, 0x00, 0x4b, 0x00, 0x04, 0x00, 0x00, 0x00];
    let expected = Nl80211Attr::WpaVersions(Nl80211WpaVersions::WPA3);
    assert_eq!(
        expected,
        Nl80211Attr::parse(&NlaBuffer::new_checked(&raw).unwrap()).unwrap()
    );
    let mut buf = vec![0; expected.buffer_len()];
    expected.emit(&mut buf);
    assert_eq!(buf, raw);
}

// NL80211_ATTR_CIPHER_SUITES_PAIRWISE = 00-0f-ac:4 (CCMP-128).
#[test]
fn test_captured_ciphers_pairwise() {
    let raw = vec![0x08, 0x00, 0x49, 0x00, 0x04, 0xac, 0x0f, 0x00];
    let expected =
        Nl80211Attr::CiphersPairwise(vec![Nl80211CipherSuite::Ccmp128]);
    assert_eq!(
        expected,
        Nl80211Attr::parse(&NlaBuffer::new_checked(&raw).unwrap()).unwrap()
    );
    let mut buf = vec![0; expected.buffer_len()];
    expected.emit(&mut buf);
    assert_eq!(buf, raw);
}

// NL80211_ATTR_CIPHER_SUITE_GROUP = 00-0f-ac:4 (CCMP-128).
#[test]
fn test_captured_cipher_group() {
    let raw = vec![0x08, 0x00, 0x4a, 0x00, 0x04, 0xac, 0x0f, 0x00];
    let expected = Nl80211Attr::CipherGroup(Nl80211CipherSuite::Ccmp128);
    assert_eq!(
        expected,
        Nl80211Attr::parse(&NlaBuffer::new_checked(&raw).unwrap()).unwrap()
    );
    let mut buf = vec![0; expected.buffer_len()];
    expected.emit(&mut buf);
    assert_eq!(buf, raw);
}

// NL80211_ATTR_AKM_SUITES = 00-0f-ac:8 (SAE).
#[test]
fn test_captured_akm_suites() {
    let raw = vec![0x08, 0x00, 0x4c, 0x00, 0x08, 0xac, 0x0f, 0x00];
    let expected = Nl80211Attr::AkmSuites(vec![Nl80211AkmSuite::Sae]);
    assert_eq!(
        expected,
        Nl80211Attr::parse(&NlaBuffer::new_checked(&raw).unwrap()).unwrap()
    );
    let mut buf = vec![0; expected.buffer_len()];
    expected.emit(&mut buf);
    assert_eq!(buf, raw);
}

// NL80211_ATTR_USE_MFP = NL80211_MFP_REQUIRED.
#[test]
fn test_captured_use_mfp() {
    let raw = vec![0x08, 0x00, 0x42, 0x00, 0x01, 0x00, 0x00, 0x00];
    let expected = Nl80211Attr::UseMfp(Nl80211UseMfp::Required);
    assert_eq!(
        expected,
        Nl80211Attr::parse(&NlaBuffer::new_checked(&raw).unwrap()).unwrap()
    );
    let mut buf = vec![0; expected.buffer_len()];
    expected.emit(&mut buf);
    assert_eq!(buf, raw);
}

// NL80211_ATTR_SOCKET_OWNER (flag).
#[test]
fn test_captured_socket_owner() {
    let raw = vec![0x04, 0x00, 0xcc, 0x00];
    let expected = Nl80211Attr::SocketOwner;
    assert_eq!(
        expected,
        Nl80211Attr::parse(&NlaBuffer::new_checked(&raw).unwrap()).unwrap()
    );
    let mut buf = vec![0; expected.buffer_len()];
    expected.emit(&mut buf);
    assert_eq!(buf, raw);
}

// NL80211_ATTR_CONTROL_PORT_OVER_NL80211 (flag) from the association request.
#[test]
fn test_captured_control_port_over_nl80211() {
    let raw = vec![0x04, 0x00, 0x08, 0x01];
    let expected = Nl80211Attr::ControlPortOverNl80211;
    assert_eq!(
        expected,
        Nl80211Attr::parse(&NlaBuffer::new_checked(&raw).unwrap()).unwrap()
    );
    let mut buf = vec![0; expected.buffer_len()];
    expected.emit(&mut buf);
    assert_eq!(buf, raw);
}

// NL80211_ATTR_STATUS_CODE = 0 (success) from the CMD_CONNECT event.
#[test]
fn test_captured_status_code() {
    let raw = vec![0x06, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x00];
    let expected = Nl80211Attr::StatusCode(0);
    assert_eq!(
        expected,
        Nl80211Attr::parse(&NlaBuffer::new_checked(&raw).unwrap()).unwrap()
    );
    let mut buf = vec![0; expected.buffer_len()];
    expected.emit(&mut buf);
    assert_eq!(buf, raw);
}

// NL80211_ATTR_IE value from the association request: the RSN information
// element (plus extended capabilities and supported operating classes) that
// wpa_supplicant inserts. Parsed with `Nl80211Elements::parse()`.
#[test]
fn test_captured_ie_rsn() {
    let raw = vec![
        0x30, 0x1a, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f,
        0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x08, 0xc0, 0x00, 0x00, 0x00,
        0x00, 0x0f, 0xac, 0x06, 0x7f, 0x0a, 0x04, 0x00, 0x4a, 0x02, 0x01, 0x40,
        0x00, 0x40, 0x00, 0x01, 0x3b, 0x17, 0x51, 0x51, 0x52, 0x53, 0x54, 0x73,
        0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
        0x80, 0x81, 0x00, 0x82, 0x80,
    ];
    let expected = Nl80211Elements(vec![
        Nl80211Element::Rsn(Nl80211ElementRsn {
            version: 1,
            group_cipher: Some(Nl80211CipherSuite::Ccmp128),
            pairwise_ciphers: vec![Nl80211CipherSuite::Ccmp128],
            akm_suits: vec![Nl80211AkmSuite::Sae],
            rsn_capbilities: Some(
                Nl80211RsnCapbilities::Mfpr | Nl80211RsnCapbilities::Mfpc,
            ),
            pmkids: vec![],
            group_mgmt_cipher: Some(Nl80211CipherSuite::BipCmac128),
        }),
        Nl80211Element::Other(127, vec![4, 0, 74, 2, 1, 64, 0, 64, 0, 1]),
        Nl80211Element::Other(
            59,
            vec![
                81, 81, 82, 83, 84, 115, 116, 117, 118, 119, 120, 121, 122,
                123, 124, 125, 126, 127, 128, 129, 0, 130, 128,
            ],
        ),
    ]);
    assert_eq!(expected, Nl80211Elements::parse(&raw).unwrap());
    let mut buf = vec![0; expected.buffer_len()];
    expected.emit(&mut buf);
    assert_eq!(buf, raw);
}

// NL80211_ATTR_FRAME: the (re)association response management frame
// delivered to userspace in the CMD_ASSOCIATE event.
#[test]
fn test_captured_frame() {
    let raw = vec![
        0x3c, 0x00, 0x33, 0x00, 0x10, 0x00, 0x3a, 0x01, 0x02, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x01, 0x00, 0xb0, 0x01, 0x11, 0x04, 0x00, 0x00, 0x01, 0xc0, 0x01, 0x08,
        0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24, 0x32, 0x04, 0x30, 0x48,
        0x60, 0x6c, 0x7f, 0x08, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
    ];
    let expected = Nl80211Attr::Frame(vec![
        0x10, 0x00, 0x3a, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0xb0, 0x01,
        0x11, 0x04, 0x00, 0x00, 0x01, 0xc0, 0x01, 0x08, 0x82, 0x84, 0x8b, 0x96,
        0x0c, 0x12, 0x18, 0x24, 0x32, 0x04, 0x30, 0x48, 0x60, 0x6c, 0x7f, 0x08,
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
    ]);
    assert_eq!(
        expected,
        Nl80211Attr::parse(&NlaBuffer::new_checked(&raw).unwrap()).unwrap()
    );
    let mut buf = vec![0; expected.buffer_len()];
    expected.emit(&mut buf);
    assert_eq!(buf, raw);
}
