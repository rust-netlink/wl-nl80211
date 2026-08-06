// SPDX-License-Identifier: MIT

// Round-trip and builder tests for the roaming-related attributes
// (`NL80211_ATTR_PREV_BSSID`, `NL80211_ATTR_PMKID`, `NL80211_ATTR_PMK`,
// `NL80211_ATTR_PMK_LIFETIME`, `NL80211_ATTR_PMK_REAUTH_THRESHOLD`) and the
// `NL80211_CMD_{SET,DEL,FLUSH}_PMKSA` / `NL80211_CMD_{SET,DEL}_PMK` request
// builders. The raw blobs are hand-built netlink attributes (length, type,
// value) padded to the 4-byte netlink alignment, mirroring the kernel's
// `nla_put` wire format.

use netlink_packet_core::{Emitable, NlaBuffer, NlasIterator, Parseable};

use crate::{
    Nl80211Associate, Nl80211Attr, Nl80211Command, Nl80211Message, Nl80211Pmk,
    Nl80211Pmksa,
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

// NL80211_ATTR_PREV_BSSID (79): the BSSID of the current AP, turning
// NL80211_CMD_ASSOCIATE into a reassociation.
#[test]
fn test_prev_bssid_roundtrip() {
    let raw = vec![
        0x0a, 0x00, 0x4f, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    ];
    assert_roundtrip(
        Nl80211Attr::PrevBssid([0x02, 0x00, 0x00, 0x00, 0x01, 0x00]),
        raw,
    );
}

// NL80211_ATTR_PREV_BSSID with an invalid length must be rejected.
#[test]
fn test_prev_bssid_invalid_len() {
    let raw = vec![0x08, 0x00, 0x4f, 0x00, 0x02, 0x00, 0x00, 0x00];
    assert!(Nl80211Attr::parse(&NlaBuffer::new_checked(&raw).unwrap()).is_err());
}

// NL80211_ATTR_PMKID (85): a 16-octet PMKID.
#[test]
fn test_pmkid_roundtrip() {
    let mut raw = vec![0x14, 0x00, 0x55, 0x00];
    raw.extend_from_slice(&[0x42; 16]);
    assert_roundtrip(Nl80211Attr::Pmkid(vec![0x42; 16]), raw);
}

// A PMKID of any length other than WLAN_PMKID_LEN (16) must be rejected.
#[test]
fn test_pmkid_invalid_len() {
    let mut raw = vec![0x0c, 0x00, 0x55, 0x00];
    raw.extend_from_slice(&[0x42; 8]);
    assert!(Nl80211Attr::parse(&NlaBuffer::new_checked(&raw).unwrap()).is_err());
}

// NL80211_ATTR_PMK (254): the PMK material (32 octets for the PSK/SAE
// AKMs).
#[test]
fn test_pmk_roundtrip() {
    let mut raw = vec![0x24, 0x00, 0xfe, 0x00];
    raw.extend_from_slice(&[0x77; 32]);
    assert_roundtrip(Nl80211Attr::Pmk(vec![0x77; 32]), raw);
}

// NL80211_ATTR_PMK_LIFETIME (287): u32 seconds.
#[test]
fn test_pmk_lifetime_roundtrip() {
    let raw = vec![0x08, 0x00, 0x1f, 0x01, 0x80, 0xa8, 0x00, 0x00];
    assert_roundtrip(Nl80211Attr::PmkLifetime(43136), raw);
}

// NL80211_ATTR_PMK_REAUTH_THRESHOLD (288): u8 percent, padded to the
// 4-byte alignment.
#[test]
fn test_pmk_reauth_threshold_roundtrip() {
    let raw = vec![0x05, 0x00, 0x20, 0x01, 0x46, 0x00, 0x00, 0x00];
    assert_roundtrip(Nl80211Attr::PmkReauthThreshold(70), raw);
}

fn emit_message_attributes(
    cmd: Nl80211Command,
    attributes: Vec<Nl80211Attr>,
) -> Vec<u8> {
    let msg = Nl80211Message { cmd, attributes };
    let mut buf = vec![0u8; msg.buffer_len()];
    msg.emit(&mut buf);
    buf
}

fn parse_message_attributes(raw: &[u8]) -> Vec<Nl80211Attr> {
    NlasIterator::new(raw)
        .map(|nla| Nl80211Attr::parse(&nla.unwrap()).unwrap())
        .collect()
}

// The association request of a reassociation carries the new BSSID in
// NL80211_ATTR_MAC and the current one in NL80211_ATTR_PREV_BSSID.
#[test]
fn test_associate_prev_bssid() {
    let buf = emit_message_attributes(
        Nl80211Command::Associate,
        Nl80211Associate::new(3)
            .mac([0x02, 0x00, 0x00, 0x00, 0x02, 0x00])
            .prev_bssid([0x02, 0x00, 0x00, 0x00, 0x01, 0x00])
            .build(),
    );
    assert_eq!(
        vec![
            Nl80211Attr::IfIndex(3),
            Nl80211Attr::Mac([0x02, 0x00, 0x00, 0x00, 0x02, 0x00]),
            Nl80211Attr::PrevBssid([0x02, 0x00, 0x00, 0x00, 0x01, 0x00]),
        ],
        parse_message_attributes(&buf)
    );
}

// NL80211_CMD_SET_PMKSA carries PMKID + MAC (BSSID) + PMK (the kernel's
// nl80211_set_pmksa requires PMKID and MAC; PMK is the cache content).
#[test]
fn test_set_pmksa_builder() {
    let buf = emit_message_attributes(
        Nl80211Command::SetPmksa,
        Nl80211Pmksa::new(3)
            .pmkid(vec![0x11; 16])
            .mac([0x02, 0x00, 0x00, 0x00, 0x01, 0x00])
            .pmk(vec![0x22; 32])
            .pmk_lifetime(43200)
            .pmk_reauth_threshold(70)
            .build(),
    );
    // The builder emits attributes sorted by their netlink kind.
    assert_eq!(
        vec![
            Nl80211Attr::IfIndex(3),
            Nl80211Attr::Mac([0x02, 0x00, 0x00, 0x00, 0x01, 0x00]),
            Nl80211Attr::Pmkid(vec![0x11; 16]),
            Nl80211Attr::Pmk(vec![0x22; 32]),
            Nl80211Attr::PmkLifetime(43200),
            Nl80211Attr::PmkReauthThreshold(70),
        ],
        parse_message_attributes(&buf)
    );
}

// NL80211_CMD_DEL_PMKSA only needs PMKID + MAC.
#[test]
fn test_del_pmksa_builder() {
    let buf = emit_message_attributes(
        Nl80211Command::DelPmksa,
        Nl80211Pmksa::new(3)
            .pmkid(vec![0x11; 16])
            .mac([0x02, 0x00, 0x00, 0x00, 0x01, 0x00])
            .build(),
    );
    assert_eq!(
        vec![
            Nl80211Attr::IfIndex(3),
            Nl80211Attr::Mac([0x02, 0x00, 0x00, 0x00, 0x01, 0x00]),
            Nl80211Attr::Pmkid(vec![0x11; 16]),
        ],
        parse_message_attributes(&buf)
    );
}

// NL80211_CMD_SET_PMK carries just the PMK material.
#[test]
fn test_set_pmk_builder() {
    let buf = emit_message_attributes(
        Nl80211Command::SetPmk,
        Nl80211Pmk::new(3).pmk(vec![0x33; 32]).build(),
    );
    assert_eq!(
        vec![Nl80211Attr::IfIndex(3), Nl80211Attr::Pmk(vec![0x33; 32])],
        parse_message_attributes(&buf)
    );
}
