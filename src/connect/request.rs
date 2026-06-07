// SPDX-License-Identifier: MIT

use futures::TryStream;
use netlink_packet_core::{Nla, NLM_F_ACK, NLM_F_REQUEST};
use netlink_packet_generic::GenlMessage;

use crate::{
    nl80211_execute, Nl80211AkmSuite, Nl80211Attr, Nl80211AttrsBuilder,
    Nl80211AuthType, Nl80211CipherSuite, Nl80211Command, Nl80211Error,
    Nl80211Handle, Nl80211Message, Nl80211UseMfp, Nl80211WpaVersions,
};

/// Helper to build the attribute list for a `NL80211_CMD_CONNECT` request.
///
/// For a typical WPA3-Personal (userspace SAE / external auth) connection use
/// [`Nl80211AttrsBuilder::<Nl80211Connect>::wpa3_personal`].
#[derive(Debug)]
pub struct Nl80211Connect;

impl Nl80211Connect {
    /// Start building a connect request for the interface `if_index`.
    pub fn new(if_index: u32) -> Nl80211AttrsBuilder<Self> {
        Nl80211AttrsBuilder::<Self>::new().if_index(if_index)
    }
}

impl Nl80211AttrsBuilder<Nl80211Connect> {
    /// Restrict the connection to a specific BSSID.
    ///
    /// Uses `NL80211_ATTR_MAC` (not `NL80211_ATTR_BSSID`, which is used by
    /// `NL80211_CMD_EXTERNAL_AUTH`), matching the kernel's convention for
    /// `NL80211_CMD_CONNECT`.
    pub fn mac(self, mac: [u8; 6]) -> Self {
        self.replace(Nl80211Attr::Mac(mac))
    }

    /// Channel frequency hint in MHz.
    pub fn frequency(self, freq_mhz: u32) -> Self {
        self.replace(Nl80211Attr::WiphyFreq(freq_mhz))
    }

    /// Authentication type, e.g. [`Nl80211AuthType::Sae`] for WPA3-Personal.
    pub fn auth_type(self, auth_type: Nl80211AuthType) -> Self {
        self.replace(Nl80211Attr::AuthType(auth_type))
    }

    /// Enabled WPA/RSN version(s).
    pub fn wpa_versions(self, versions: Nl80211WpaVersions) -> Self {
        self.replace(Nl80211Attr::WpaVersions(versions))
    }

    /// Unicast (pairwise) cipher suite(s).
    pub fn ciphers_pairwise(self, ciphers: Vec<Nl80211CipherSuite>) -> Self {
        self.replace(Nl80211Attr::CiphersPairwise(ciphers))
    }

    /// Group (broadcast/multicast) cipher suite.
    pub fn cipher_group(self, cipher: Nl80211CipherSuite) -> Self {
        self.replace(Nl80211Attr::CipherGroup(cipher))
    }

    /// Authentication and Key Management (AKM) suite(s).
    pub fn akm_suites(self, akms: Vec<Nl80211AkmSuite>) -> Self {
        self.replace(Nl80211Attr::AkmSuites(akms))
    }

    /// Indicate that userspace will perform the authentication (e.g. SAE)
    /// externally. The kernel/driver will emit a `NL80211_CMD_EXTERNAL_AUTH`
    /// event to drive the exchange. This is the portable path for
    /// WPA3-Personal on drivers that do not advertise SAE offload.
    pub fn external_auth_support(self, enable: bool) -> Self {
        if enable {
            self.replace(Nl80211Attr::ExternalAuthSupport)
        } else {
            self.remove(Nl80211Attr::ExternalAuthSupport.kind())
        }
    }

    /// Whether the target BSS is privacy-enabled (encrypted).
    pub fn privacy(self, enable: bool) -> Self {
        if enable {
            self.replace(Nl80211Attr::Privacy)
        } else {
            self.remove(Nl80211Attr::Privacy.kind())
        }
    }

    /// Management frame protection (IEEE 802.11w) mode.
    pub fn use_mfp(self, mfp: Nl80211UseMfp) -> Self {
        self.replace(Nl80211Attr::UseMfp(mfp))
    }

    /// Request that EAPOL (802.1X) control port frames are sent/received over
    /// nl80211. When enabled, [`socket_owner`](Self::socket_owner) must also
    /// be set.
    pub fn control_port_over_nl80211(self, enable: bool) -> Self {
        if enable {
            self.replace(Nl80211Attr::ControlPortOverNl80211)
        } else {
            self.remove(Nl80211Attr::ControlPortOverNl80211.kind())
        }
    }

    /// Mark the requesting socket as the owner of the connection, so it is
    /// torn down when the socket is closed.
    pub fn socket_owner(self, enable: bool) -> Self {
        if enable {
            self.replace(Nl80211Attr::SocketOwner)
        } else {
            self.remove(Nl80211Attr::SocketOwner.kind())
        }
    }

    /// Extra information element(s) (e.g. a custom RSN element) to add to the
    /// association request.
    pub fn ie(self, ie: Vec<u8>) -> Self {
        self.replace(Nl80211Attr::Ie(ie))
    }

    /// Configure all crypto attributes for a standard WPA3-Personal (SAE)
    /// connection using CCMP-128 and required management frame protection,
    /// performing the SAE authentication in userspace (external auth).
    ///
    /// No password is passed to the kernel; userspace must run the SAE
    /// exchange in response to the `NL80211_CMD_EXTERNAL_AUTH` event and
    /// transmit the Authentication frames via `NL80211_CMD_FRAME`.
    ///
    /// The caller still needs to set [`ssid`](Self::ssid) (and optionally
    /// [`mac`](Self::mac)).
    pub fn wpa3_personal(self) -> Self {
        self.auth_type(Nl80211AuthType::Sae)
            .wpa_versions(Nl80211WpaVersions::WPA2)
            .ciphers_pairwise(vec![Nl80211CipherSuite::Ccmp128])
            .cipher_group(Nl80211CipherSuite::Ccmp128)
            .akm_suites(vec![Nl80211AkmSuite::Sae])
            .use_mfp(Nl80211UseMfp::Required)
            .privacy(true)
            .external_auth_support(true)
    }
}

pub struct Nl80211ConnectRequest {
    handle: Nl80211Handle,
    attributes: Vec<Nl80211Attr>,
}

impl Nl80211ConnectRequest {
    pub(crate) fn new(
        handle: Nl80211Handle,
        attributes: Vec<Nl80211Attr>,
    ) -> Self {
        Nl80211ConnectRequest { handle, attributes }
    }

    /// Send the `NL80211_CMD_CONNECT` request.
    ///
    /// A successful return only means the request was accepted by the kernel;
    /// the actual connection result is delivered asynchronously as a
    /// `NL80211_CMD_CONNECT` event on the multicast group.
    pub async fn execute(
        self,
    ) -> impl TryStream<Ok = GenlMessage<Nl80211Message>, Error = Nl80211Error>
    {
        let Nl80211ConnectRequest {
            mut handle,
            attributes,
        } = self;

        let nl80211_msg = Nl80211Message {
            cmd: Nl80211Command::Connect,
            attributes,
        };
        let flags = NLM_F_REQUEST | NLM_F_ACK;

        nl80211_execute(&mut handle, nl80211_msg, flags).await
    }
}
