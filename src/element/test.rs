// SPDX-License-Identifier: MIT

use netlink_packet_core::{Emitable, Parseable};

use super::{
    Nl80211AkmSuite, Nl80211CipherSuite, Nl80211Element, Nl80211ElementCountry,
    Nl80211ElementCountryEnvironment, Nl80211ElementCountryTriplet,
    Nl80211ElementRsn, Nl80211ElementSubBand, Nl80211RateAndSelector,
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
