// SPDX-License-Identifier: MIT

// On-wire `NL80211_ATTR_*` bytes captured on the `nl0` netlink monitor while a
// WPA3-Personal connection (hostapd + mac80211_hwsim, driven by
// wpa_supplicant) was torn down. The blobs are taken from the
// `NL80211_CMD_DEAUTHENTICATE` request/event and the `NL80211_CMD_DISCONNECT`
// event. Each `raw` is a single netlink attribute (length, type, value), padded
// to the netlink 4-byte alignment, with the unrelated message/genl headers
// stripped. They validate our parsing and emitting against what the kernel and
// userspace exchange.

use netlink_packet_core::{Emitable, NlaBuffer, Parseable};

use crate::Nl80211Attr;

// NL80211_ATTR_REASON_CODE = 3 ("Deauthenticated because sending STA is
// leaving the BSS"). These exact bytes appear in both the
// CMD_DEAUTHENTICATE request and the CMD_DISCONNECT event.
#[test]
fn test_captured_reason_code() {
    let raw = vec![0x06, 0x00, 0x36, 0x00, 0x03, 0x00, 0x00, 0x00];
    let expected = Nl80211Attr::ReasonCode(3);
    assert_eq!(
        expected,
        Nl80211Attr::parse(&NlaBuffer::new_checked(&raw).unwrap()).unwrap()
    );
    let mut buf = vec![0; expected.buffer_len()];
    expected.emit(&mut buf);
    assert_eq!(buf, raw);
}

// NL80211_ATTR_MAC: the BSSID the STA deauthenticates from, taken from the
// CMD_DEAUTHENTICATE request (02:00:00:00:01:00).
#[test]
fn test_captured_deauthenticate_mac() {
    let raw = vec![
        0x0a, 0x00, 0x06, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    ];
    let expected = Nl80211Attr::Mac([0x02, 0x00, 0x00, 0x00, 0x01, 0x00]);
    assert_eq!(
        expected,
        Nl80211Attr::parse(&NlaBuffer::new_checked(&raw).unwrap()).unwrap()
    );
    let mut buf = vec![0; expected.buffer_len()];
    expected.emit(&mut buf);
    assert_eq!(buf, raw);
}

// NL80211_ATTR_FRAME: the Deauthentication management frame delivered to
// userspace in the CMD_DEAUTHENTICATE event. Value length 26 bytes, so the
// attribute is padded to 32.
#[test]
fn test_captured_deauthenticate_frame() {
    let raw = vec![
        0x1e, 0x00, 0x33, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
    ];
    let expected = Nl80211Attr::Frame(vec![
        0xc0, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x03, 0x00,
    ]);
    assert_eq!(
        expected,
        Nl80211Attr::parse(&NlaBuffer::new_checked(&raw).unwrap()).unwrap()
    );
    let mut buf = vec![0; expected.buffer_len()];
    expected.emit(&mut buf);
    assert_eq!(buf, raw);
}
