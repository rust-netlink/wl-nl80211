// SPDX-License-Identifier: MIT

use futures::TryStream;
use netlink_packet_core::{NLM_F_ACK, NLM_F_REQUEST};
use netlink_packet_generic::GenlMessage;

use crate::{
    Ieee80211AkmSuite, Ieee80211CipherSuite, Nl80211Attr, Nl80211AttrsBuilder,
    Nl80211AuthType, Nl80211Command, Nl80211Error, Nl80211Handle,
    Nl80211Message, Nl80211WpaVersions, nl80211_execute,
};

/// `NL80211_HIDDEN_SSID_NOT_IN_USE`.
pub const NL80211_HIDDEN_SSID_NOT_IN_USE: u32 = 0;
/// `NL80211_HIDDEN_SSID_ZERO_LEN`: hide the SSID by sending a zero-length
/// SSID in beacons.
pub const NL80211_HIDDEN_SSID_ZERO_LEN: u32 = 1;
/// `NL80211_HIDDEN_SSID_ZERO_CONTENTS`: hide the SSID by zeroing its
/// contents in beacons.
pub const NL80211_HIDDEN_SSID_ZERO_CONTENTS: u32 = 2;

/// Builder for `NL80211_CMD_START_AP` / `NL80211_CMD_NEW_BEACON`.
///
/// The kernel builds beacons, probe responses and association responses
/// from the supplied beacon head/tail and IE attributes; the userspace AP
/// MLME still handles authentication and association frames itself.
#[derive(Debug)]
pub struct Nl80211StartAp;

impl Nl80211StartAp {
    /// Start building a START_AP request for the AP interface `if_index`.
    pub fn new(if_index: u32) -> Nl80211AttrsBuilder<Self> {
        Nl80211AttrsBuilder::<Self>::new().if_index(if_index)
    }
}

impl Nl80211AttrsBuilder<Nl80211StartAp> {
    /// Operating channel frequency in MHz.
    pub fn frequency(self, freq_mhz: u32) -> Self {
        self.replace(Nl80211Attr::WiphyFreq(freq_mhz))
    }

    /// Beacon interval in TUs.
    pub fn beacon_interval(self, interval: u32) -> Self {
        self.replace(Nl80211Attr::BeaconInterval(interval))
    }

    /// DTIM period.
    pub fn dtim_period(self, period: u32) -> Self {
        self.replace(Nl80211Attr::DtimPeriod(period))
    }

    /// Portion of the beacon before the TIM element.
    pub fn beacon_head(self, head: Vec<u8>) -> Self {
        self.replace(Nl80211Attr::BeaconHead(head))
    }

    /// Portion of the beacon after the TIM element.
    pub fn beacon_tail(self, tail: Vec<u8>) -> Self {
        self.replace(Nl80211Attr::BeaconTail(tail))
    }

    /// Hidden SSID mode, one of the `NL80211_HIDDEN_SSID_*` constants.
    pub fn hidden_ssid(self, mode: u32) -> Self {
        self.replace(Nl80211Attr::HiddenSsid(mode))
    }

    /// Mark the BSS as privacy enabled (encrypted).
    pub fn privacy(self, enable: bool) -> Self {
        if enable {
            self.replace(Nl80211Attr::Privacy)
        } else {
            self
        }
    }

    /// Authentication algorithm used by the BSS.
    pub fn auth_type(self, auth_type: Nl80211AuthType) -> Self {
        self.replace(Nl80211Attr::AuthType(auth_type))
    }

    /// WPA/RSN protocol versions supported by the BSS.
    pub fn wpa_versions(self, versions: Nl80211WpaVersions) -> Self {
        self.replace(Nl80211Attr::WpaVersions(versions))
    }

    /// AKM suites supported by the BSS.
    pub fn akm_suites(self, suites: Vec<Ieee80211AkmSuite>) -> Self {
        self.replace(Nl80211Attr::AkmSuites(suites))
    }

    /// Pairwise cipher suites supported by the BSS.
    pub fn ciphers_pairwise(self, suites: Vec<Ieee80211CipherSuite>) -> Self {
        self.replace(Nl80211Attr::CiphersPairwise(suites))
    }

    /// Group cipher suite used by the BSS.
    pub fn cipher_group(self, suite: Ieee80211CipherSuite) -> Self {
        self.replace(Nl80211Attr::CipherGroup(suite))
    }

    /// Additional information elements appended to beacons.
    pub fn ie(self, ie: Vec<u8>) -> Self {
        self.replace(Nl80211Attr::Ie(ie))
    }

    /// Information elements appended to probe responses.
    pub fn ie_probe_resp(self, ie: Vec<u8>) -> Self {
        self.replace(Nl80211Attr::IeProbeResp(ie))
    }

    /// Information elements appended to (re)association responses.
    pub fn ie_assoc_resp(self, ie: Vec<u8>) -> Self {
        self.replace(Nl80211Attr::IeAssocResp(ie))
    }

    /// Full probe response template (`NL80211_ATTR_PROBE_RESP`).
    pub fn probe_resp(self, resp: Vec<u8>) -> Self {
        self.replace(Nl80211Attr::ProbeResp(resp))
    }

    /// Inactivity timeout in seconds.
    pub fn inactivity_timeout(self, seconds: u16) -> Self {
        self.replace(Nl80211Attr::InactivityTimeout(seconds))
    }

    /// AP settings flags (`NL80211_ATTR_AP_SETTINGS_FLAGS`).
    pub fn ap_settings_flags(self, flags: u32) -> Self {
        self.replace(Nl80211Attr::ApSettingsFlags(flags))
    }

    /// Basic rates for the BSS.
    pub fn basic_rates(self, rates: Vec<u8>) -> Self {
        self.replace(Nl80211Attr::BssBasicRates(rates))
    }
}

/// Sends a `NL80211_CMD_START_AP` request.
pub struct Nl80211StartApRequest {
    handle: Nl80211Handle,
    attributes: Vec<Nl80211Attr>,
}

impl Nl80211StartApRequest {
    pub(crate) fn new(
        handle: Nl80211Handle,
        attributes: Vec<Nl80211Attr>,
    ) -> Self {
        Self { handle, attributes }
    }

    pub async fn execute(
        self,
    ) -> impl TryStream<Ok = GenlMessage<Nl80211Message>, Error = Nl80211Error>
    {
        let Self {
            mut handle,
            attributes,
        } = self;
        nl80211_execute(
            &mut handle,
            Nl80211Message {
                cmd: Nl80211Command::StartAp,
                attributes,
            },
            NLM_F_REQUEST | NLM_F_ACK,
        )
        .await
    }
}

/// Builder for `NL80211_CMD_STOP_AP`, which stops beaconing and tears down
/// the BSS on an AP interface.
#[derive(Debug)]
pub struct Nl80211StopAp;

impl Nl80211StopAp {
    /// Start building a STOP_AP request for the AP interface `if_index`.
    pub fn new(if_index: u32) -> Nl80211AttrsBuilder<Self> {
        Nl80211AttrsBuilder::<Self>::new().if_index(if_index)
    }
}

/// Sends a `NL80211_CMD_STOP_AP` request.
pub struct Nl80211StopApRequest {
    handle: Nl80211Handle,
    attributes: Vec<Nl80211Attr>,
}

impl Nl80211StopApRequest {
    pub(crate) fn new(
        handle: Nl80211Handle,
        attributes: Vec<Nl80211Attr>,
    ) -> Self {
        Self { handle, attributes }
    }

    pub async fn execute(
        self,
    ) -> impl TryStream<Ok = GenlMessage<Nl80211Message>, Error = Nl80211Error>
    {
        let Self {
            mut handle,
            attributes,
        } = self;
        nl80211_execute(
            &mut handle,
            Nl80211Message {
                cmd: Nl80211Command::StopAp,
                attributes,
            },
            NLM_F_REQUEST | NLM_F_ACK,
        )
        .await
    }
}
