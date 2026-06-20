// SPDX-License-Identifier: MIT

use netlink_packet_core::{Emitable, Parseable};

use super::{
    Nl80211AkmSuite, Nl80211CipherSuite, Nl80211Element, Nl80211ElementCountry,
    Nl80211ElementCountryEnvironment, Nl80211ElementCountryTriplet,
    Nl80211ElementRsn, Nl80211ElementRsnExt, Nl80211ElementSubBand,
    Nl80211RateAndSelector, Nl80211RsnExtCapbilities,
};

#[test]
fn ssid() {
    let val: Nl80211Element = Nl80211Element::Ssid("test-ssid".to_owned());
    let mut buffer = vec![0; val.buffer_len() + 1];
    val.emit(buffer.as_mut_slice());
    assert_eq!(
        <Nl80211Element>::parse(&buffer[0..val.buffer_len()]).unwrap(),
        val,
    );
}

#[test]
fn rates_and_selectors() {
    let val: Nl80211Element = Nl80211Element::SupportedRatesAndSelectors(vec![
        Nl80211RateAndSelector::BssBasicRateSet(1),
        Nl80211RateAndSelector::Rate(1),
        Nl80211RateAndSelector::SelectorHt,
        Nl80211RateAndSelector::SelectorVht,
        Nl80211RateAndSelector::SelectorGlk,
    ]);
    let mut buffer = vec![0; val.buffer_len() + 1];
    val.emit(buffer.as_mut_slice());
    assert_eq!(
        <Nl80211Element>::parse(&buffer[0..val.buffer_len()]).unwrap(),
        val,
    );
}

#[test]
fn channel() {
    let val: Nl80211Element = Nl80211Element::Channel(7);
    let mut buffer = vec![0; val.buffer_len() + 1];
    val.emit(buffer.as_mut_slice());
    assert_eq!(
        <Nl80211Element>::parse(&buffer[0..val.buffer_len()]).unwrap(),
        val,
    );
}

#[test]
fn country() {
    let val: Nl80211Element = Nl80211Element::Country(Nl80211ElementCountry {
        country: "DE".to_owned(),
        environment: Nl80211ElementCountryEnvironment::IndoorAndOutdoor,
        triplets: vec![Nl80211ElementCountryTriplet::Subband(
            Nl80211ElementSubBand {
                channel_start: 1,
                channel_count: 13,
                max_power_level: 20,
            },
        )],
    });
    let mut buffer = vec![0; val.buffer_len() + 1];
    val.emit(buffer.as_mut_slice());
    assert_eq!(
        <Nl80211Element>::parse(&buffer[0..val.buffer_len()]).unwrap(),
        val,
    );
}

#[test]
fn rsn() {
    let val: Nl80211Element = Nl80211Element::Rsn(Nl80211ElementRsn {
        version: 1,
        group_cipher: Some(Nl80211CipherSuite::Ccmp128),
        pairwise_ciphers: vec![Nl80211CipherSuite::Ccmp128],
        akm_suits: vec![Nl80211AkmSuite::Psk],
        rsn_capbilities: None,
        pmkids: Vec::new(),
        group_mgmt_cipher: None,
    });
    let mut buffer = vec![0; val.buffer_len() + 1];
    val.emit(buffer.as_mut_slice());
    assert_eq!(
        <Nl80211Element>::parse(&buffer[0..val.buffer_len()]).unwrap(),
        val,
    );
}

// Extended RSN Capabilities element (RSNXE) advertising SAE Hash-to-Element.
// `f4 01 20` was captured from a hostapd WPA3 AP's beacon on an nlmon monitor:
// element id 244, length 1, value 0x20 (Field length subfield 0, SAE-H2E bit).
#[test]
fn rsn_ext_sae_h2e_captured() {
    let raw = vec![0xf4, 0x01, 0x20];
    let val = Nl80211Element::RsnExt(Nl80211ElementRsnExt {
        capabilities: Nl80211RsnExtCapbilities::SaeH2e,
    });
    let mut buffer = vec![0; val.buffer_len()];
    val.emit(buffer.as_mut_slice());
    assert_eq!(buffer, raw);
    assert_eq!(<Nl80211Element>::parse(&raw).unwrap(), val);
}

#[test]
fn rsn_ext_multi_octet() {
    // SsidProtection is bit 21 -> requires a 3-octet field (Field length 2).
    let val = Nl80211Element::RsnExt(Nl80211ElementRsnExt {
        capabilities: Nl80211RsnExtCapbilities::SaeH2e
            | Nl80211RsnExtCapbilities::SsidProtection,
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
    assert_eq!(<Nl80211Element>::parse(&raw).unwrap(), val);
}

// A capability bit beyond the u32 range (a 5-octet field with a bit in the
// 5th octet) must round-trip, exercising the u128 backing storage. The Field
// length subfield is 4 (n - 1 = 5 - 1).
#[test]
fn rsn_ext_beyond_u32() {
    let raw = vec![0xf4, 0x05, 0x04, 0x00, 0x00, 0x00, 0x80];
    let val = <Nl80211Element>::parse(&raw).unwrap();
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
    let parsed = Nl80211ElementRsnExt::parse(&payload).unwrap();
    assert_eq!(
        parsed.capabilities,
        Nl80211RsnExtCapbilities::SaeH2e,
        "trailing 0xff beyond the field length must be ignored"
    );
}
