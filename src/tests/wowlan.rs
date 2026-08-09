// SPDX-License-Identifier: MIT

// Round-trip tests for the WoWLAN attributes of `NL80211_CMD_SET_WOWLAN`:
// `NL80211_ATTR_WOWLAN_TRIGGERS` (the triggers a STA arms before suspend
// and, after resume, the triggers that fired in the kernel's wake
// notification). The `raw` blobs are wire-format examples (len u16 LE,
// kind u16 LE, value, padded to 4 bytes); the trigger payload below was
// validated against a real `iw phy ... wowlan enable disconnect
// gtk-rekey-failure` capture on `nl0` (mac80211_hwsim). There is no
// nlmon capture for the wake *event* itself (mac80211_hwsim has no
// WoWLAN support).

use netlink_packet_core::{DefaultNla, Emitable, NlaBuffer, Parseable};

use crate::{
    Nl80211Attr, Nl80211Wowlan, Nl80211WowlanTriggersSupport,
    Nl80211WowlanWakeup,
};

// NL80211_ATTR_WOWLAN_TRIGGERS = 117, nested value with two empty trigger
// NLAs: Disconnect (kind 2) then GtkRekeyFailure (kind 6). Each empty NLA
// is exactly 4 bytes (`04 00 <kind-le16>`), already aligned. The payload
// matches the captured `iw ... wowlan enable` request; the same shape
// appears in the SET_WOWLAN wake notification.
#[test]
fn test_wowlan_triggers_round_trip() {
    let raw = vec![
        0x0c, 0x00, 0x75, 0x00, 0x04, 0x00, 0x02, 0x00, 0x04, 0x00, 0x06, 0x00,
    ];
    let expected = Nl80211Attr::WowlanTriggers(vec![
        Nl80211WowlanTriggersSupport::Disconnect,
        Nl80211WowlanTriggersSupport::GtkRekeyFailure,
    ]);
    assert_eq!(
        expected,
        Nl80211Attr::parse(&NlaBuffer::new_checked(&raw).unwrap()).unwrap()
    );
    let mut buf = vec![0; expected.buffer_len()];
    expected.emit(&mut buf);
    assert_eq!(buf, raw);
}

// A single wake reason NLA: GtkRekeyFailure uses the trigger kind 6 in
// the wake notification too (there is no separate wakeup numbering).
#[test]
fn test_wowlan_wakeup_reason_round_trip() {
    let raw = vec![0x04, 0x00, 0x06, 0x00];
    let expected = Nl80211WowlanWakeup::GtkRekeyFailure;
    assert_eq!(
        expected,
        Nl80211WowlanWakeup::parse(&NlaBuffer::new_checked(&raw).unwrap())
            .unwrap()
    );
    let mut buf = vec![0; expected.buffer_len()];
    expected.emit(&mut buf);
    assert_eq!(buf, raw);
}

// A wake notification carries a pattern-index NLA (kind 4, u32 payload)
// where the support enum expects the 16-byte pattern struct; the
// attribute must not fail the decode, it falls back to `Other`.
#[test]
fn test_wowlan_triggers_unmodeled_payload_is_lenient() {
    let raw = vec![
        0x0c, 0x00, 0x75, 0x00, 0x08, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00,
    ];
    let expected =
        Nl80211Attr::WowlanTriggers(vec![Nl80211WowlanTriggersSupport::Other(
            DefaultNla::new(4, vec![0x01, 0x00, 0x00, 0x00]),
        )]);
    assert_eq!(
        expected,
        Nl80211Attr::parse(&NlaBuffer::new_checked(&raw).unwrap()).unwrap()
    );
    let mut buf = vec![0; expected.buffer_len()];
    expected.emit(&mut buf);
    assert_eq!(buf, raw);
}

// The `Nl80211Wowlan` builder produces the attribute list for a
// `NL80211_CMD_SET_WOWLAN` request.
#[test]
fn test_wowlan_request_builder() {
    let attrs = Nl80211Wowlan::new(12)
        .triggers(vec![
            Nl80211WowlanTriggersSupport::Disconnect,
            Nl80211WowlanTriggersSupport::GtkRekeyFailure,
        ])
        .build();
    assert_eq!(
        attrs,
        vec![
            Nl80211Attr::IfIndex(12),
            Nl80211Attr::WowlanTriggers(vec![
                Nl80211WowlanTriggersSupport::Disconnect,
                Nl80211WowlanTriggersSupport::GtkRekeyFailure,
            ]),
        ]
    );
}
