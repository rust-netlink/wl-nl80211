// SPDX-License-Identifier: MIT

// IEEE 802.11 SSID holds 0..32 arbitrary octets, it is not required to be a
// valid UTF-8 string (e.g. GBK encoded AP names are common). The parser
// therefore always stores the SSID octets verbatim in the `SsidRaw`
// variants, and adds the `Ssid` string view as well when the octets are
// valid UTF-8, so a received SSID can neither be mangled nor fail a parse.
// Only the raw attribute is emitted.

use netlink_packet_core::{Emitable, Parseable, ParseableParametrized};
use netlink_packet_generic::GenlHeader;

use crate::{
    Ieee80211Element, Ieee80211Elements, Nl80211Attr, Nl80211Command,
    Nl80211Message, Nl80211SchedScanMatch, Nl80211SchedScanMatchAttr,
};

const NL80211_CMD_GET_SCAN: u8 = 32;

// GBK encoded '无线', invalid UTF-8.
const NON_UTF8_SSID: [u8; 4] = [0xce, 0xde, 0xcf, 0xdf];

/// Emit `attrs` as the attribute region of a nl80211 message.
fn emit(attrs: &[Nl80211Attr]) -> Vec<u8> {
    let mut raw = vec![0; attrs.buffer_len()];
    attrs.emit(&mut raw);
    raw
}

/// Emit `elements` as the information elements of a frame.
fn emit_elements(elements: &[Ieee80211Element]) -> Vec<u8> {
    let elements = Ieee80211Elements(elements.to_vec());
    let mut raw = vec![0; elements.buffer_len()];
    elements.emit(&mut raw);
    raw
}

/// Parse the attribute region of a nl80211 message.
fn parse(raw: &[u8]) -> Nl80211Message {
    Nl80211Message::parse_with_param(
        raw,
        GenlHeader {
            cmd: NL80211_CMD_GET_SCAN,
            version: 1,
        },
    )
    .unwrap()
}

#[test]
fn ie_ssid_keeps_raw_and_string_view() {
    // A single element is stored raw, the string view is added by the list
    // parser.
    let element = Ieee80211Element::SsidRaw(b"Test-WIFI".to_vec());
    let mut buffer = vec![0; element.buffer_len()];
    element.emit(&mut buffer);
    assert_eq!(Ieee80211Element::parse(&buffer).unwrap(), element);

    for ssid in [b"Test-WIFI".to_vec(), b"Test\0WIFI".to_vec()] {
        let raw = emit_elements(&[Ieee80211Element::SsidRaw(ssid.clone())]);
        assert_eq!(
            Ieee80211Elements::parse(&raw).unwrap().0,
            vec![
                Ieee80211Element::SsidRaw(ssid.clone()),
                Ieee80211Element::Ssid(String::from_utf8(ssid).unwrap()),
            ]
        );
    }

    // A SSID which is not valid UTF-8 has no string view.
    let raw =
        emit_elements(&[Ieee80211Element::SsidRaw(NON_UTF8_SSID.to_vec())]);
    assert_eq!(
        Ieee80211Elements::parse(&raw).unwrap().0,
        vec![Ieee80211Element::SsidRaw(NON_UTF8_SSID.to_vec())]
    );
}

// A valid UTF-8 SSID is stored raw and as string, a SSID holding a NUL is
// kept verbatim rather than being trimmed.
#[test]
fn attr_ssid_keeps_raw_and_string_view() {
    for ssid in [b"Test-WIFI".to_vec(), b"Test\0WIFI".to_vec()] {
        let raw = emit(&[Nl80211Attr::SsidRaw(ssid.clone())]);
        assert_eq!(
            parse(&raw).attributes,
            vec![
                Nl80211Attr::SsidRaw(ssid.clone()),
                Nl80211Attr::Ssid(String::from_utf8(ssid).unwrap()),
            ]
        );
    }
}

#[test]
fn attr_ssid_without_utf8_has_no_string_view() {
    let raw = emit(&[Nl80211Attr::SsidRaw(NON_UTF8_SSID.to_vec())]);
    assert_eq!(
        parse(&raw).attributes,
        vec![Nl80211Attr::SsidRaw(NON_UTF8_SSID.to_vec())]
    );
}

// NL80211_ATTR_SCAN_SSIDS carries one SSID per child NLA, the kernel
// multicasts it back with TRIGGER_SCAN/NEW_SCAN_RESULTS.
#[test]
fn scan_ssids_keep_raw_and_string_view() {
    let raw = emit(&[Nl80211Attr::ScanSsidsRaw(vec![
        b"Test-WIFI".to_vec(),
        Vec::new(),
    ])]);
    assert_eq!(
        parse(&raw).attributes,
        vec![
            Nl80211Attr::ScanSsidsRaw(vec![b"Test-WIFI".to_vec(), Vec::new()]),
            Nl80211Attr::ScanSsids(vec![
                "Test-WIFI".to_string(),
                String::new()
            ]),
        ]
    );

    // One SSID which is not valid UTF-8 leaves the string view out.
    let raw = emit(&[Nl80211Attr::ScanSsidsRaw(vec![
        NON_UTF8_SSID.to_vec(),
        b"Test-WIFI".to_vec(),
    ])]);
    assert_eq!(
        parse(&raw).attributes,
        vec![Nl80211Attr::ScanSsidsRaw(vec![
            NON_UTF8_SSID.to_vec(),
            b"Test-WIFI".to_vec(),
        ])]
    );
}

// The string view is only a convenience for consumers, the raw attribute is
// the one which goes back on the wire.
#[test]
fn string_view_is_not_emitted() {
    for attrs in [
        vec![Nl80211Attr::SsidRaw(b"Test-WIFI".to_vec())],
        vec![Nl80211Attr::ScanSsidsRaw(vec![b"Test-WIFI".to_vec()])],
    ] {
        let raw = emit(&attrs);
        let msg = parse(&raw);
        assert_eq!(msg.cmd, Nl80211Command::GetScan);
        assert_eq!(msg.attributes.len(), 2);

        let mut re_emitted = vec![0; msg.buffer_len()];
        msg.emit(&mut re_emitted);
        assert_eq!(re_emitted, raw);
    }
}

// The raw attribute wins over the string one, whatever their content.
#[test]
fn raw_ssid_is_preferred_over_string() {
    let msg = Nl80211Message {
        cmd: Nl80211Command::GetScan,
        attributes: vec![
            Nl80211Attr::Ssid("String-SSID".to_string()),
            Nl80211Attr::SsidRaw(b"Raw-SSID".to_vec()),
        ],
    };
    let mut buffer = vec![0; msg.buffer_len()];
    msg.emit(&mut buffer);
    assert_eq!(buffer, emit(&[Nl80211Attr::SsidRaw(b"Raw-SSID".to_vec())]));

    // Without a raw SSID the string one is emitted.
    let msg = Nl80211Message {
        cmd: Nl80211Command::GetScan,
        attributes: vec![Nl80211Attr::Ssid("String-SSID".to_string())],
    };
    let mut buffer = vec![0; msg.buffer_len()];
    msg.emit(&mut buffer);
    assert_eq!(
        buffer,
        emit(&[Nl80211Attr::Ssid("String-SSID".to_string())])
    );
}

// The string variants are used when building a message, they emit the same
// octets as their raw counterpart.
#[test]
fn string_variants_emit_octets() {
    assert_eq!(
        emit(&[Nl80211Attr::Ssid("Test-WIFI".to_string())]),
        emit(&[Nl80211Attr::SsidRaw(b"Test-WIFI".to_vec())])
    );
    assert_eq!(
        emit(&[Nl80211Attr::ScanSsids(vec!["Test-WIFI".to_string()])]),
        emit(&[Nl80211Attr::ScanSsidsRaw(vec![b"Test-WIFI".to_vec()])])
    );

    let element = Ieee80211Element::Ssid("Test-WIFI".to_string());
    let mut buffer = vec![0; element.buffer_len()];
    element.emit(&mut buffer);
    assert_eq!(
        Ieee80211Element::parse(&buffer).unwrap(),
        Ieee80211Element::SsidRaw(b"Test-WIFI".to_vec())
    );
}

// NL80211_SCHED_SCAN_MATCH_ATTR_SSID is parsed by the nested match set
// parser, which stores the SSID raw and adds the string view.
#[test]
fn sched_scan_match_ssid_keeps_raw_and_string_view() {
    for (ssid, expected) in [
        (
            b"WifiRefTest".to_vec(),
            vec![
                Nl80211SchedScanMatchAttr::SsidRaw(b"WifiRefTest".to_vec()),
                Nl80211SchedScanMatchAttr::Ssid("WifiRefTest".to_string()),
            ],
        ),
        (
            NON_UTF8_SSID.to_vec(),
            vec![Nl80211SchedScanMatchAttr::SsidRaw(NON_UTF8_SSID.to_vec())],
        ),
    ] {
        let attrs =
            vec![Nl80211Attr::SchedScanMatch(vec![Nl80211SchedScanMatch(
                vec![Nl80211SchedScanMatchAttr::SsidRaw(ssid)],
            )])];
        let raw = emit(&attrs);
        let msg = parse(&raw);
        assert_eq!(
            msg.attributes,
            vec![Nl80211Attr::SchedScanMatch(vec![Nl80211SchedScanMatch(
                expected
            )])]
        );

        // The string view is not emitted.
        let mut re_emitted = vec![0; msg.buffer_len()];
        msg.emit(&mut re_emitted);
        assert_eq!(re_emitted, raw);
    }
}
