// SPDX-License-Identifier: MIT

use netlink_packet_core::{NLM_F_ACK, NLM_F_REQUEST, Nla};

use crate::{
    Ieee80211CipherSuite, Nl80211Attr, Nl80211AuthType, Nl80211Command,
    Nl80211StartAp, Nl80211StationAdd, Nl80211StationFlagUpdate,
    Nl80211StationFlags, Nl80211StopAp, Nl80211WpaVersions,
};

fn emit(attr: &Nl80211Attr) -> Vec<u8> {
    let mut buf = Vec::new();
    attr.emit(&mut buf).expect("emit attribute");
    buf
}

fn find<'a>(
    attrs: &'a [Nl80211Attr],
    matcher: impl Fn(&Nl80211Attr) -> bool,
) -> &'a Nl80211Attr {
    attrs
        .iter()
        .find(|a| matcher(a))
        .expect("attribute present")
}

#[test]
fn test_start_ap_attributes() {
    let attrs = Nl80211StartAp::new(7)
        .beacon_interval(100)
        .dtim_period(2)
        .beacon_head(vec![1, 2, 3])
        .beacon_tail(vec![4, 5])
        .hidden_ssid(crate::NL80211_HIDDEN_SSID_NOT_IN_USE)
        .privacy(true)
        .auth_type(Nl80211AuthType::OpenSystem)
        .wpa_versions(Nl80211WpaVersions::WPA2)
        .akm_suites(vec![crate::Ieee80211AkmSuite::Psk])
        .ciphers_pairwise(vec![Ieee80211CipherSuite::Ccmp128])
        .cipher_group(Ieee80211CipherSuite::Ccmp128)
        .ie(vec![6, 7])
        .ie_probe_resp(vec![8])
        .ie_assoc_resp(vec![9])
        .inactivity_timeout(300)
        .basic_rates(vec![0x82, 0x84, 0x8b, 0x96])
        .ssid("Test-WIFI")
        .build();

    assert_eq!(
        find(&attrs, |a| matches!(a, Nl80211Attr::BeaconInterval(_))).kind(),
        12
    );
    assert_eq!(
        emit(find(&attrs, |a| matches!(a, Nl80211Attr::DtimPeriod(_)))),
        vec![5, 0, 13, 0, 0x02, 0, 0, 0]
    );
    assert_eq!(
        emit(find(&attrs, |a| matches!(a, Nl80211Attr::BeaconHead(_)))),
        vec![7, 0, 14, 0, 1, 2, 3, 0]
    );
    assert_eq!(
        emit(find(&attrs, |a| matches!(a, Nl80211Attr::BeaconTail(_)))),
        vec![6, 0, 15, 0, 4, 5, 0, 0]
    );
    assert!(matches!(
        find(&attrs, |a| matches!(a, Nl80211Attr::HiddenSsid(_))),
        Nl80211Attr::HiddenSsid(crate::NL80211_HIDDEN_SSID_NOT_IN_USE)
    ));
    assert!(matches!(
        find(&attrs, |a| matches!(a, Nl80211Attr::Privacy)),
        Nl80211Attr::Privacy
    ));
    assert!(matches!(
        find(&attrs, |a| matches!(a, Nl80211Attr::IeProbeResp(_))),
        Nl80211Attr::IeProbeResp(v) if v == &vec![8]
    ));
    assert!(matches!(
        find(&attrs, |a| matches!(a, Nl80211Attr::IeAssocResp(_))),
        Nl80211Attr::IeAssocResp(v) if v == &vec![9]
    ));
    assert_eq!(
        emit(find(&attrs, |a| matches!(
            a,
            Nl80211Attr::InactivityTimeout(_)
        ))),
        vec![6, 0, 150, 0, 0x2c, 0x01, 0, 0]
    );
}

#[test]
fn test_station_add_attributes() {
    let update = Nl80211StationFlagUpdate {
        mask: Nl80211StationFlags::Authorized
            | Nl80211StationFlags::Authenticated
            | Nl80211StationFlags::Associated,
        set: Nl80211StationFlags::Authorized
            | Nl80211StationFlags::Authenticated
            | Nl80211StationFlags::Associated,
    };
    let attrs = Nl80211StationAdd::new(7, [0x02, 0, 0, 0, 0, 1])
        .aid(1)
        .listen_interval(10)
        .supported_rates(vec![0x82, 0x84])
        .capability(0x0431)
        .flags2(update)
        .ext_capability(vec![0x00, 0x00])
        .build();

    assert!(matches!(
        find(&attrs, |a| matches!(a, Nl80211Attr::Mac(_))),
        Nl80211Attr::Mac([0x02, 0, 0, 0, 0, 1])
    ));
    assert_eq!(
        emit(find(&attrs, |a| matches!(a, Nl80211Attr::StaAid(_)))),
        vec![6, 0, 16, 0, 0x01, 0, 0, 0]
    );
    assert_eq!(
        emit(find(&attrs, |a| matches!(a, Nl80211Attr::StaCapability(_)))),
        vec![6, 0, 171, 0, 0x31, 0x04, 0, 0]
    );
    assert_eq!(
        emit(find(&attrs, |a| matches!(a, Nl80211Attr::StaFlags2(_)))),
        vec![
            12, 0, 67, 0, // length, type
            0xa2, 0x00, 0x00, 0x00, // mask
            0xa2, 0x00, 0x00, 0x00, // set
        ]
    );
}

#[test]
fn test_ap_commands() {
    assert_eq!(u8::from(Nl80211Command::StartAp), 15);
    assert_eq!(u8::from(Nl80211Command::StopAp), 16);
    assert_eq!(u8::from(Nl80211Command::NewStation), 19);
    assert_eq!(u8::from(Nl80211Command::SetStation), 18);
    assert_eq!(u8::from(Nl80211Command::DelStation), 20);
    assert_eq!(NLM_F_REQUEST | NLM_F_ACK, 0x0005);
    let _ = Nl80211StopAp::new(7);
}
