// SPDX-License-Identifier: MIT

// On-wire `NL80211_ATTR_*` bytes captured on the `nl0` netlink monitor on
// mac80211_hwsim. `NL80211_ATTR_FRAME_TYPE` and `NL80211_ATTR_FRAME_MATCH`
// were taken from the `NL80211_CMD_REGISTER_FRAME` messages wpa_supplicant
// emits when it initialises on an interface to register for management frames.
// `NL80211_ATTR_PRIVACY` was taken from a `NL80211_CMD_CONNECT` issued with
// `iw dev <ifname> connect <ssid> <bssid> key 0:<wepkey>`. Each `raw` blob is a
// single netlink attribute (length, type, value) padded to the netlink 4-byte
// alignment.

use netlink_packet_core::{Emitable, NlaBuffer, Parseable};

use crate::Nl80211Attr;

// NL80211_ATTR_FRAME_TYPE = 0x00d0 (IEEE 802.11 management Action frame), from
// CMD_REGISTER_FRAME.
#[test]
fn test_captured_frame_type() {
    let raw = vec![0x06, 0x00, 0x65, 0x00, 0xd0, 0x00, 0x00, 0x00];
    let expected = Nl80211Attr::FrameType(0x00d0);
    assert_eq!(
        expected,
        Nl80211Attr::parse(&NlaBuffer::new_checked(&raw).unwrap()).unwrap()
    );
    let mut buf = vec![0; expected.buffer_len()];
    expected.emit(&mut buf);
    assert_eq!(buf, raw);
}

// NL80211_ATTR_FRAME_MATCH: the management frame body prefix to match, from
// CMD_REGISTER_FRAME.
#[test]
fn test_captured_frame_match() {
    let raw = vec![0x06, 0x00, 0x5b, 0x00, 0x01, 0x04, 0x00, 0x00];
    let expected = Nl80211Attr::FrameMatch(vec![0x01, 0x04]);
    assert_eq!(
        expected,
        Nl80211Attr::parse(&NlaBuffer::new_checked(&raw).unwrap()).unwrap()
    );
    let mut buf = vec![0; expected.buffer_len()];
    expected.emit(&mut buf);
    assert_eq!(buf, raw);
}

// NL80211_ATTR_PRIVACY: flag indicating the BSS uses privacy (protected
// frames), from CMD_CONNECT.
#[test]
fn test_captured_privacy() {
    let raw = vec![0x04, 0x00, 0x46, 0x00];
    let expected = Nl80211Attr::Privacy;
    assert_eq!(
        expected,
        Nl80211Attr::parse(&NlaBuffer::new_checked(&raw).unwrap()).unwrap()
    );
    let mut buf = vec![0; expected.buffer_len()];
    expected.emit(&mut buf);
    assert_eq!(buf, raw);
}
