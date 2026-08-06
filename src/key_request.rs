// SPDX-License-Identifier: MIT

use futures::TryStream;
use netlink_packet_core::{NLM_F_ACK, NLM_F_REQUEST};
use netlink_packet_generic::GenlMessage;

use crate::{
    nl80211_execute, Nl80211Attr, Nl80211CipherSuite, Nl80211Command,
    Nl80211Error, Nl80211Handle, Nl80211KeyAttr, Nl80211KeyDefaultType,
    Nl80211KeyType, Nl80211Message,
};

/// Helper to build the attribute list for a `NL80211_CMD_NEW_KEY` request
/// (key installation).
///
/// For station mode `NL80211_CMD_NEW_KEY` alone is enough: the kernel
/// selects the GTK for RX by the Key ID subfield in the CCMP header
/// (802.11-2020 §12.5.3.2), so no `NL80211_CMD_SET_KEY` is required.
#[derive(Debug)]
pub struct Nl80211Key;

impl Nl80211Key {
    /// Start building a `NL80211_CMD_NEW_KEY` request for `if_index`.
    #[allow(clippy::new_ret_no_self)]
    pub fn new(if_index: u32) -> Nl80211KeyRequestBuilder {
        Nl80211KeyRequestBuilder {
            if_index,
            mac: None,
            key_data: Vec::new(),
            key_index: 0,
            cipher: Nl80211CipherSuite::Ccmp128,
            seq: None,
            key_type: None,
            default_mgmt: false,
            default_types: Vec::new(),
        }
    }

    /// Convenience for installing the pairwise (unicast) key: CCMP-128 at
    /// key index 0 for `peer_mac`.
    pub fn new_ptk(
        if_index: u32,
        peer_mac: [u8; 6],
        key_data: Vec<u8>,
    ) -> Nl80211KeyRequestBuilder {
        Self::new(if_index)
            .mac(peer_mac)
            .key_data(key_data)
            .key_type(Nl80211KeyType::Pairwise)
    }

    /// Convenience for installing a group (multicast) key: CCMP-128 at
    /// `key_index`, marked as the default multicast key via
    /// `NL80211_KEY_DEFAULT_TYPES` (`NL80211_KEY_DEFAULT_TYPE_MULTICAST`).
    pub fn new_gtk(
        if_index: u32,
        key_data: Vec<u8>,
        key_index: u8,
    ) -> Nl80211KeyRequestBuilder {
        Self::new(if_index)
            .key_data(key_data)
            .key_index(key_index)
            .key_type(Nl80211KeyType::Group)
            .default_types(vec![Nl80211KeyDefaultType::Multicast])
    }

    /// Convenience for installing an Integrity GTK (IEEE 802.11w / PMF):
    /// BIP-CMAC-128 at `key_index` (4-5, as assigned by the AP), with `seq`
    /// holding the 6-octet IPN (receive sequence counter) from the IGTK KDE,
    /// marked as the default management-frame key
    /// (`NL80211_KEY_DEFAULT_MGMT`).
    pub fn new_igtk(
        if_index: u32,
        key_data: Vec<u8>,
        key_index: u8,
        seq: Vec<u8>,
    ) -> Nl80211KeyRequestBuilder {
        Self::new(if_index)
            .key_data(key_data)
            .key_index(key_index)
            .cipher(Nl80211CipherSuite::BipCmac128)
            .seq(seq)
            .key_type(Nl80211KeyType::Group)
            .default_mgmt(true)
    }

    /// Convenience for installing a Beacon Integrity GTK (IEEE 802.11w-2024
    /// beacon protection): BIP-CMAC-128 at `key_index` (6-7), with `seq`
    /// holding the 6-octet IPN from the BIGTK KDE. The BIGTK is RX-only
    /// (beacon protection) and never the default TX management key.
    pub fn new_bigtk(
        if_index: u32,
        key_data: Vec<u8>,
        key_index: u8,
        seq: Vec<u8>,
    ) -> Nl80211KeyRequestBuilder {
        Self::new(if_index)
            .key_data(key_data)
            .key_index(key_index)
            .cipher(Nl80211CipherSuite::BipCmac128)
            .seq(seq)
            .key_type(Nl80211KeyType::Group)
    }
}

/// Builder for the attributes of a `NL80211_CMD_NEW_KEY` request.
#[derive(Debug)]
pub struct Nl80211KeyRequestBuilder {
    if_index: u32,
    mac: Option<[u8; 6]>,
    key_data: Vec<u8>,
    key_index: u8,
    cipher: Nl80211CipherSuite,
    seq: Option<Vec<u8>>,
    key_type: Option<Nl80211KeyType>,
    default_mgmt: bool,
    default_types: Vec<Nl80211KeyDefaultType>,
}

impl Nl80211KeyRequestBuilder {
    /// The peer the pairwise key belongs to; omit for group keys.
    pub fn mac(mut self, mac: [u8; 6]) -> Self {
        self.mac = Some(mac);
        self
    }

    /// Key material (e.g. the 16-byte CCMP temporal key).
    pub fn key_data(mut self, data: Vec<u8>) -> Self {
        self.key_data = data;
        self
    }

    /// Key index: 0 for the pairwise key, 1-3 for group keys.
    pub fn key_index(mut self, idx: u8) -> Self {
        self.key_index = idx;
        self
    }

    /// Cipher suite, e.g. [`Nl80211CipherSuite::Ccmp128`].
    pub fn cipher(mut self, cipher: Nl80211CipherSuite) -> Self {
        self.cipher = cipher;
        self
    }

    /// Receive sequence counter (RSC) / packet number.
    pub fn seq(mut self, seq: Vec<u8>) -> Self {
        self.seq = Some(seq);
        self
    }

    /// Key type (pairwise / group / PMK).
    pub fn key_type(mut self, key_type: Nl80211KeyType) -> Self {
        self.key_type = Some(key_type);
        self
    }

    /// Mark the key as the default management-frame (BIP) key
    /// (`NL80211_KEY_DEFAULT_MGMT`), used when installing the IGTK.
    pub fn default_mgmt(mut self, enable: bool) -> Self {
        self.default_mgmt = enable;
        self
    }

    /// Traffic types this key is the default for.
    pub fn default_types(
        mut self,
        default_types: Vec<Nl80211KeyDefaultType>,
    ) -> Self {
        self.default_types = default_types;
        self
    }

    /// Build the attribute list for a `NL80211_CMD_NEW_KEY` request.
    pub fn build(self) -> Vec<Nl80211Attr> {
        // `Nl80211CipherSuite` stores the 802.11 element byte-order; the
        // netlink `NL80211_KEY_CIPHER` attribute expects the kernel's u32
        // (OUI in the high bytes), so swap — see the `CiphersPairwise` emit
        // in `attr.rs`.
        let cipher = u32::from(self.cipher).swap_bytes();
        let mut key = vec![
            Nl80211KeyAttr::Data(self.key_data),
            Nl80211KeyAttr::Cipher(cipher),
        ];
        if let Some(seq) = self.seq {
            key.push(Nl80211KeyAttr::Seq(seq));
        }
        key.push(Nl80211KeyAttr::Idx(self.key_index));
        if let Some(key_type) = self.key_type {
            key.push(Nl80211KeyAttr::Type(key_type));
        }
        if self.default_mgmt {
            key.push(Nl80211KeyAttr::DefaultMgmt);
        }
        if !self.default_types.is_empty() {
            key.push(Nl80211KeyAttr::DefaultTypes(self.default_types));
        }
        let mut attributes = vec![Nl80211Attr::IfIndex(self.if_index)];
        if let Some(mac) = self.mac {
            attributes.push(Nl80211Attr::Mac(mac));
        }
        attributes.push(Nl80211Attr::Key(key));
        attributes
    }
}

/// Sends a `NL80211_CMD_NEW_KEY` request.
pub struct Nl80211KeyRequest {
    handle: Nl80211Handle,
    attributes: Vec<Nl80211Attr>,
}

impl Nl80211KeyRequest {
    pub(crate) fn new(
        handle: Nl80211Handle,
        attributes: Vec<Nl80211Attr>,
    ) -> Self {
        Nl80211KeyRequest { handle, attributes }
    }

    /// Send the `NL80211_CMD_NEW_KEY` request.
    ///
    /// A successful return only means the key was accepted by the kernel.
    pub async fn execute(
        self,
    ) -> impl TryStream<Ok = GenlMessage<Nl80211Message>, Error = Nl80211Error>
    {
        let Nl80211KeyRequest {
            mut handle,
            attributes,
        } = self;
        let nl80211_msg = Nl80211Message {
            cmd: Nl80211Command::NewKey,
            attributes,
        };
        nl80211_execute(&mut handle, nl80211_msg, NLM_F_REQUEST | NLM_F_ACK)
            .await
    }
}
