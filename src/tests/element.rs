// SPDX-License-Identifier: MIT

use netlink_packet_core::{Emitable, Parseable};

use super::{
    Ieee80211AkmSuite, Ieee80211CipherSuite, Ieee80211Element, Ieee80211ElementCountry,
    Ieee80211ElementCountryEnvironment, Ieee80211ElementCountryTriplet,
    Ieee80211ElementRsn, Ieee80211ElementRsnExt, Ieee80211ElementSubBand,
    Ieee80211RateAndSelector, Ieee80211RsnExtCapbilities,
};

#[test]
fn ssid() {
    let val: Ieee80211Element = Ieee80211Element::Ssid("test-ssid".to_owned());
    let mut buffer = vec![0; val.buffer_len() + 1];
    val.emit(buffer.as_mut_slice());
    assert_eq!(
        <Ieee80211Element>::parse(&buffer[0..val.buffer_len()]).unwrap(),
        val,
    );
}

#[test]
fn rates_and_selectors() {
    let val: Ieee80211Element = Ieee80211Element::SupportedRatesAndSelectors(vec![
        Ieee80211RateAndSelector::BssBasicRateSet(1),
        Ieee80211RateAndSelector::Rate(1),
        Ieee80211RateAndSelector::SelectorHt,
        Ieee80211RateAndSelector::SelectorVht,
        Ieee80211RateAndSelector::SelectorGlk,
        Ieee80211RateAndSelector::SelectorEht,
    ]);
    let mut buffer = vec![0; val.buffer_len() + 1];
    val.emit(buffer.as_mut_slice());
    assert_eq!(
        <Ieee80211Element>::parse(&buffer[0..val.buffer_len()]).unwrap(),
        val,
    );
}

#[test]
fn channel() {
    let val: Ieee80211Element = Ieee80211Element::Channel(7);
    let mut buffer = vec![0; val.buffer_len() + 1];
    val.emit(buffer.as_mut_slice());
    assert_eq!(
        <Ieee80211Element>::parse(&buffer[0..val.buffer_len()]).unwrap(),
        val,
    );
}

#[test]
fn country() {
    let val: Ieee80211Element = Ieee80211Element::Country(Ieee80211ElementCountry {
        country: "DE".to_owned(),
        environment: Ieee80211ElementCountryEnvironment::IndoorAndOutdoor,
        triplets: vec![Ieee80211ElementCountryTriplet::Subband(
            Ieee80211ElementSubBand {
                channel_start: 1,
                channel_count: 13,
                max_power_level: 20,
            },
        )],
    });
    let mut buffer = vec![0; val.buffer_len() + 1];
    val.emit(buffer.as_mut_slice());
    assert_eq!(
        <Ieee80211Element>::parse(&buffer[0..val.buffer_len()]).unwrap(),
        val,
    );
}

#[test]
fn rsn() {
    let val: Ieee80211Element = Ieee80211Element::Rsn(Ieee80211ElementRsn {
        version: 1,
        group_cipher: Some(Ieee80211CipherSuite::Ccmp128),
        pairwise_ciphers: vec![Ieee80211CipherSuite::Ccmp128],
        akm_suits: vec![Ieee80211AkmSuite::Psk],
        rsn_capbilities: None,
        pmkids: Vec::new(),
        group_mgmt_cipher: None,
    });
    let mut buffer = vec![0; val.buffer_len() + 1];
    val.emit(buffer.as_mut_slice());
    assert_eq!(
        <Ieee80211Element>::parse(&buffer[0..val.buffer_len()]).unwrap(),
        val,
    );
}

// Extended RSN Capabilities element (RSNXE) advertising SAE Hash-to-Element.
// `f4 01 20` was captured from a hostapd WPA3 AP's beacon on an nlmon monitor:
// element id 244, length 1, value 0x20 (Field length subfield 0, SAE-H2E bit).
#[test]
fn rsn_ext_sae_h2e_captured() {
    let raw = vec![0xf4, 0x01, 0x20];
    let val = Ieee80211Element::RsnExt(Ieee80211ElementRsnExt {
        capabilities: Ieee80211RsnExtCapbilities::SaeH2e,
    });
    let mut buffer = vec![0; val.buffer_len()];
    val.emit(buffer.as_mut_slice());
    assert_eq!(buffer, raw);
    assert_eq!(<Ieee80211Element>::parse(&raw).unwrap(), val);
}

#[test]
fn rsn_ext_multi_octet() {
    // SsidProtection is bit 21 -> requires a 3-octet field (Field length 2).
    let val = Ieee80211Element::RsnExt(Ieee80211ElementRsnExt {
        capabilities: Ieee80211RsnExtCapbilities::SaeH2e
            | Ieee80211RsnExtCapbilities::SsidProtection,
    });
    // id, len=3, then field: octet0 = len-nibble(2) | SAE-H2E(0x20) = 0x22,
    // octet1 = 0, octet2 = bit21 = 0x20.
    assert_eq!(
        {
            let mut b = vec![0; val.buffer_len()];
            val.emit(b.as_mut_slice());
            b
        },
        vec![0xf4, 0x03, 0x22, 0x00, 0x20],
    );
    let raw = vec![0xf4, 0x03, 0x22, 0x00, 0x20];
    assert_eq!(<Ieee80211Element>::parse(&raw).unwrap(), val);
}

// A capability bit beyond the u32 range (a 5-octet field with a bit in the
// 5th octet) must round-trip, exercising the u128 backing storage. The Field
// length subfield is 4 (n - 1 = 5 - 1).
#[test]
fn rsn_ext_beyond_u32() {
    let raw = vec![0xf4, 0x05, 0x04, 0x00, 0x00, 0x00, 0x80];
    let val = <Ieee80211Element>::parse(&raw).unwrap();
    let mut buffer = vec![0; val.buffer_len()];
    val.emit(buffer.as_mut_slice());
    assert_eq!(buffer, raw);
}

// The Field length subfield (low nibble of the first octet) is authoritative:
// trailing bytes beyond it must not be parsed as extra capability bits. Here
// the subfield says n = 1 (one octet, SAE-H2E) but a stray 0xff trails it.
#[test]
fn rsn_ext_ignores_trailing_bytes() {
    let payload = vec![0x20, 0xff];
    let parsed = Ieee80211ElementRsnExt::parse(&payload).unwrap();
    assert_eq!(
        parsed.capabilities,
        Ieee80211RsnExtCapbilities::SaeH2e,
        "trailing 0xff beyond the field length must be ignored"
    );
}
