// SPDX-License-Identifier: MIT

use futures::TryStream;
use netlink_packet_core::{EthernetProtocol, Nla, NLM_F_ACK, NLM_F_REQUEST};
use netlink_packet_generic::GenlMessage;

use crate::{
    nl80211_execute, Nl80211AkmSuite, Nl80211Attr, Nl80211AttrsBuilder,
    Nl80211CipherSuite, Nl80211Command, Nl80211Error, Nl80211Handle,
    Nl80211Message, Nl80211UseMfp, Nl80211WpaVersions,
};

/// Helper to build the attribute list for a `NL80211_CMD_ASSOCIATE` request.
///
/// Typically used right after a successful [`crate::Nl80211Authenticate`]
/// exchange. The RSN information element (via [`ie`](Self::ie)) must match
/// the one used in the 4-way handshake, as the AP verifies the consistency.
#[derive(Debug)]
pub struct Nl80211Associate;

impl Nl80211Associate {
    /// Start building an associate request for the interface `if_index`.
    pub fn new(if_index: u32) -> Nl80211AttrsBuilder<Self> {
        Nl80211AttrsBuilder::<Self>::new().if_index(if_index)
    }
}

impl Nl80211AttrsBuilder<Nl80211Associate> {
    /// BSSID of the AP to associate with.
    pub fn mac(self, mac: [u8; 6]) -> Self {
        self.replace(Nl80211Attr::Mac(mac))
    }

    /// Channel frequency hint in MHz.
    pub fn frequency(self, freq_mhz: u32) -> Self {
        self.replace(Nl80211Attr::WiphyFreq(freq_mhz))
    }

    /// Extra information element(s) to add to the association request, e.g.
    /// the RSN element built for the network's security mode.
    pub fn ie(self, ie: Vec<u8>) -> Self {
        self.replace(Nl80211Attr::Ie(ie))
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

    /// Ethernet protocol of the control port frames (normally
    /// [`EthernetProtocol::Pae`], `ETH_P_PAE` = 0x888E).
    pub fn control_port_ethertype(self, ethertype: EthernetProtocol) -> Self {
        self.replace(Nl80211Attr::ControlPortEthertype(u16::from(ethertype)))
    }
}

pub struct Nl80211AssociateRequest {
    handle: Nl80211Handle,
    attributes: Vec<Nl80211Attr>,
}

impl Nl80211AssociateRequest {
    pub(crate) fn new(
        handle: Nl80211Handle,
        attributes: Vec<Nl80211Attr>,
    ) -> Self {
        Nl80211AssociateRequest { handle, attributes }
    }

    /// Send the `NL80211_CMD_ASSOCIATE` request.
    ///
    /// A successful return only means the request was accepted by the kernel;
    /// the association result is delivered asynchronously as a
    /// `NL80211_CMD_ASSOCIATE` event on the multicast group.
    pub async fn execute(
        self,
    ) -> impl TryStream<Ok = GenlMessage<Nl80211Message>, Error = Nl80211Error>
    {
        let Nl80211AssociateRequest {
            mut handle,
            attributes,
        } = self;

        let nl80211_msg = Nl80211Message {
            cmd: Nl80211Command::Associate,
            attributes,
        };
        let flags = NLM_F_REQUEST | NLM_F_ACK;

        nl80211_execute(&mut handle, nl80211_msg, flags).await
    }
}
