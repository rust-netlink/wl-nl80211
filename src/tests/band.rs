// SPDX-License-Identifier: MIT

use crate::Ieee80211OperatingClass;

#[test]
fn operating_class_channel_to_freq_2ghz() {
    assert_eq!(
        Ieee80211OperatingClass::from(81).channel_to_freq(1),
        Some(2412)
    );
    assert_eq!(
        Ieee80211OperatingClass::from(81).channel_to_freq(6),
        Some(2437)
    );
    assert_eq!(
        Ieee80211OperatingClass::from(81).channel_to_freq(13),
        Some(2472)
    );
    assert_eq!(
        Ieee80211OperatingClass::from(82).channel_to_freq(14),
        Some(2484)
    );
    assert_eq!(Ieee80211OperatingClass::from(81).channel_to_freq(14), None);
}

#[test]
fn operating_class_channel_to_freq_5ghz() {
    assert_eq!(
        Ieee80211OperatingClass::from(115).channel_to_freq(36),
        Some(5180)
    );
    assert_eq!(
        Ieee80211OperatingClass::from(124).channel_to_freq(149),
        Some(5745)
    );
    assert_eq!(
        Ieee80211OperatingClass::from(128).channel_to_freq(177),
        Some(5885)
    );
    assert_eq!(Ieee80211OperatingClass::from(115).channel_to_freq(20), None);
}

#[test]
fn operating_class_channel_to_freq_6ghz() {
    assert_eq!(
        Ieee80211OperatingClass::from(131).channel_to_freq(1),
        Some(5955)
    );
    assert_eq!(
        Ieee80211OperatingClass::from(131).channel_to_freq(5),
        Some(5975)
    );
    assert_eq!(
        Ieee80211OperatingClass::from(155).channel_to_freq(233),
        Some(7115)
    );
    assert_eq!(Ieee80211OperatingClass::from(131).channel_to_freq(2), None);
}

#[test]
fn operating_class_channel_to_freq_unknown() {
    assert_eq!(Ieee80211OperatingClass::from(200).channel_to_freq(1), None);
    assert_eq!(Ieee80211OperatingClass::from(0).channel_to_freq(6), None);
}
