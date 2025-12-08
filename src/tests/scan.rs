// SPDX-License-Identifier: MIT

use crate::*;
use netlink_packet_core::{
    Emitable, NetlinkDeserializable, NetlinkHeader, Parseable,
};
use netlink_packet_generic::{GenlHeader, GenlMessage};

const NL80211_CMD_TRIGGER_SCAN: u8 = 33;
const NL80211_CMD_GET_SCAN: u8 = 32;
const NL80211_CMD_NEW_SCAN_RESULTS: u8 = 34;

// nlmon capture of `iw wlan0 scan`
// The raw data is copied since the generic netlink command property.
#[test]
fn test_trigger_scan() {
    let raw = vec![
        0x21, 0x00, 0x00, 0x00, 0x08, 0x00, 0x03, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x2d, 0x00, 0x04, 0x00, 0x01, 0x00, 0x08, 0x00, 0x9e, 0x00,
        0x00, 0x40, 0x00, 0x00,
    ];

    let family_id = 0x26;

    let expected = GenlMessage::new(
        GenlHeader {
            cmd: NL80211_CMD_TRIGGER_SCAN,
            version: 0,
        },
        Nl80211Message {
            cmd: Nl80211Command::TriggerScan,
            attributes: vec![
                Nl80211Attr::IfIndex(2),
                Nl80211Attr::ScanSsids(vec![String::new()]),
                Nl80211Attr::ScanFlags(Nl80211ScanFlags::Colocated6Ghz),
            ],
        },
        family_id,
    );

    let mut netlink_header = NetlinkHeader::default();

    netlink_header.message_type = family_id;

    assert_eq!(
        expected,
        GenlMessage::<Nl80211Message>::deserialize(&netlink_header, &raw,)
            .unwrap()
    );

    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    assert_eq!(buf, raw);
}

// nlmon capture of `iw dev wlan0 scan dump`
// The raw data is copied since the generic netlink command property.
#[test]
fn test_get_scan() {
    let raw = vec![
        0x20, 0x00, 0x00, 0x00, 0x08, 0x00, 0x03, 0x00, 0x15, 0x00, 0x00, 0x00,
    ];

    let family_id = 0x2e;

    let expected = GenlMessage::new(
        GenlHeader {
            cmd: NL80211_CMD_GET_SCAN,
            version: 0,
        },
        Nl80211Message {
            cmd: Nl80211Command::GetScan,
            attributes: vec![Nl80211Attr::IfIndex(21)],
        },
        family_id,
    );

    let mut netlink_header = NetlinkHeader::default();

    netlink_header.message_type = family_id;

    assert_eq!(
        expected,
        GenlMessage::<Nl80211Message>::deserialize(&netlink_header, &raw,)
            .unwrap()
    );

    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    assert_eq!(buf, raw);
}

// nlmon capture of `iw dev wlan0 scan dump` reply.
// The raw data is copied since the generic netlink command property.
#[test]
fn test_get_scan_reply() {
    let raw = vec![
        0x22, 0x01, 0x00, 0x00, 0x08, 0x00, 0x2e, 0x00, 0x1e, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x03, 0x00, 0x15, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x99, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x0c, 0x01, 0x2f, 0x00,
        0x0a, 0x00, 0x01, 0x00, 0xd6, 0xb2, 0x6a, 0xa8, 0xbc, 0xb1, 0x00, 0x00,
        0x04, 0x00, 0x0e, 0x00, 0x0c, 0x00, 0x03, 0x00, 0x6e, 0xb2, 0x8d, 0xd3,
        0x66, 0x45, 0x06, 0x00, 0x49, 0x00, 0x06, 0x00, 0x00, 0x09, 0x54, 0x65,
        0x73, 0x74, 0x2d, 0x57, 0x49, 0x46, 0x49, 0x01, 0x08, 0x82, 0x84, 0x8b,
        0x96, 0x0c, 0x12, 0x18, 0x24, 0x03, 0x01, 0x01, 0x2a, 0x01, 0x04, 0x32,
        0x04, 0x30, 0x48, 0x60, 0x6c, 0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac,
        0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac,
        0x08, 0xc0, 0x00, 0x3b, 0x02, 0x51, 0x00, 0x7f, 0x08, 0x04, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x0d, 0x00,
        0xcd, 0x60, 0x8d, 0xd3, 0x66, 0x45, 0x06, 0x00, 0x4f, 0x00, 0x0b, 0x00,
        0x00, 0x09, 0x54, 0x65, 0x73, 0x74, 0x2d, 0x57, 0x49, 0x46, 0x49, 0x01,
        0x08, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24, 0x03, 0x01, 0x01,
        0x05, 0x04, 0x00, 0x02, 0x00, 0x00, 0x2a, 0x01, 0x04, 0x32, 0x04, 0x30,
        0x48, 0x60, 0x6c, 0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01,
        0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x08, 0xc0,
        0x00, 0x3b, 0x02, 0x51, 0x00, 0x7f, 0x08, 0x04, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x40, 0x00, 0x06, 0x00, 0x04, 0x00, 0x64, 0x00, 0x00, 0x00,
        0x06, 0x00, 0x05, 0x00, 0x11, 0x04, 0x00, 0x00, 0x08, 0x00, 0x02, 0x00,
        0x6c, 0x09, 0x00, 0x00, 0x08, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x0a, 0x00, 0x9f, 0x2f, 0x00, 0x00, 0x0c, 0x00, 0x0f, 0x00,
        0x50, 0x43, 0xf2, 0xea, 0x15, 0x99, 0x00, 0x00, 0x08, 0x00, 0x07, 0x00,
        0x48, 0xf4, 0xff, 0xff, 0x08, 0x00, 0x17, 0x00, 0x03, 0x00, 0x00, 0x00,
    ];

    let family_id = 0x2e;

    let expected = GenlMessage::new(
        GenlHeader {
            cmd: NL80211_CMD_NEW_SCAN_RESULTS,
            version: 1,
        },
        Nl80211Message {
            cmd: Nl80211Command::NewScanResults,
            attributes: vec![
                Nl80211Attr::Generation(30),
                Nl80211Attr::IfIndex(21),
                Nl80211Attr::Wdev(25769803777),
                Nl80211Attr::Bss(vec![
                    Nl80211BssInfo::Bssid([214, 178, 106, 168, 188, 177]),
                    Nl80211BssInfo::RawProbeResponseInformationElements(vec![]),
                    Nl80211BssInfo::Tsf(1765157798523502),
                    Nl80211BssInfo::RawInformationElements(vec![
                        0, 9, 84, 101, 115, 116, 45, 87, 73, 70, 73, 1, 8, 130,
                        132, 139, 150, 12, 18, 24, 36, 3, 1, 1, 42, 1, 4, 50,
                        4, 48, 72, 96, 108, 48, 20, 1, 0, 0, 15, 172, 4, 1, 0,
                        0, 15, 172, 4, 1, 0, 0, 15, 172, 8, 192, 0, 59, 2, 81,
                        0, 127, 8, 4, 0, 0, 0, 0, 0, 0, 64,
                    ]),
                    Nl80211BssInfo::BeaconTsf(1765157798502605),
                    Nl80211BssInfo::RawBeaconInformationElements(vec![
                        0, 9, 84, 101, 115, 116, 45, 87, 73, 70, 73, 1, 8, 130,
                        132, 139, 150, 12, 18, 24, 36, 3, 1, 1, 5, 4, 0, 2, 0,
                        0, 42, 1, 4, 50, 4, 48, 72, 96, 108, 48, 20, 1, 0, 0,
                        15, 172, 4, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 8,
                        192, 0, 59, 2, 81, 0, 127, 8, 4, 0, 0, 0, 0, 0, 0, 64,
                    ]),
                    Nl80211BssInfo::BeaconInterval(100),
                    Nl80211BssInfo::Capability(
                        Nl80211BssCapabilities::Ess
                            | Nl80211BssCapabilities::Privacy
                            | Nl80211BssCapabilities::ShortSlotTime,
                    ),
                    Nl80211BssInfo::Frequency(2412),
                    Nl80211BssInfo::FrequencyOffset(0),
                    Nl80211BssInfo::SeenMsAgo(12191),
                    Nl80211BssInfo::LastSeenBootTime(168319415108432),
                    Nl80211BssInfo::SignalMbm(-3000),
                    Nl80211BssInfo::UseFor(
                        Nl80211BssUseFor::Normal | Nl80211BssUseFor::MldLink,
                    ),
                ]),
            ],
        },
        family_id,
    );

    let mut netlink_header = NetlinkHeader::default();

    netlink_header.message_type = family_id;

    assert_eq!(
        expected,
        GenlMessage::<Nl80211Message>::deserialize(&netlink_header, &raw,)
            .unwrap()
    );

    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    assert_eq!(buf, raw);
}

#[test]
fn test_parse_ies() {
    let raw = vec![
        0x49, 0x00, 0x06, 0x00, 0x00, 0x09, 0x54, 0x65, 0x73, 0x74, 0x2d, 0x57,
        0x49, 0x46, 0x49, 0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18,
        0x24, 0x03, 0x01, 0x01, 0x2a, 0x01, 0x04, 0x32, 0x04, 0x30, 0x48, 0x60,
        0x6c, 0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00,
        0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x08, 0xc0, 0x00, 0x3b,
        0x02, 0x51, 0x00, 0x7f, 0x08, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x40,
    ];

    let expected = Nl80211Elements(vec![
        Nl80211Element::Other(73, vec![]),
        Nl80211Element::Other(6, vec![]),
        Nl80211Element::Ssid("Test-WIFI".to_string()),
        Nl80211Element::SupportedRatesAndSelectors(vec![
            Nl80211RateAndSelector::BssBasicRateSet(2),
            Nl80211RateAndSelector::BssBasicRateSet(4),
            Nl80211RateAndSelector::BssBasicRateSet(11),
            Nl80211RateAndSelector::BssBasicRateSet(22),
            Nl80211RateAndSelector::Rate(12),
            Nl80211RateAndSelector::Rate(18),
            Nl80211RateAndSelector::Rate(24),
            Nl80211RateAndSelector::Rate(36),
        ]),
        Nl80211Element::Channel(1),
        Nl80211Element::Other(42, vec![4]),
        Nl80211Element::Other(50, vec![48, 72, 96, 108]),
        Nl80211Element::Rsn(Nl80211ElementRsn {
            version: 1,
            group_cipher: Some(Nl80211CipherSuite::Ccmp128),
            pairwise_ciphers: vec![Nl80211CipherSuite::Ccmp128],
            akm_suits: vec![Nl80211AkmSuite::Sae],
            rsn_capbilities: Some(
                Nl80211RsnCapbilities::Mfpr | Nl80211RsnCapbilities::Mfpc,
            ),
            pmkids: vec![],
            group_mgmt_cipher: None,
        }),
        Nl80211Element::Other(59, vec![81, 0]),
        Nl80211Element::Other(127, vec![4, 0, 0, 0, 0, 0, 0, 64]),
    ]);

    assert_eq!(expected, Nl80211Elements::parse(&raw).unwrap());

    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    assert_eq!(buf, raw);
}
