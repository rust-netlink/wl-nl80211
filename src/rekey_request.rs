// SPDX-License-Identifier: MIT

use futures::TryStream;
use netlink_packet_core::{NLM_F_ACK, NLM_F_REQUEST};
use netlink_packet_generic::GenlMessage;

use crate::{
    nl80211_execute, Nl80211AkmSuite, Nl80211Attr, Nl80211Command,
    Nl80211Error, Nl80211Handle, Nl80211Message, Nl80211RekeyData,
};

/// Helper to build the attribute list for a `NL80211_CMD_SET_REKEY_OFFLOAD`
/// request, handing GTK rekey material to the driver/firmware so the device
/// can keep receiving while the host is suspended.
///
/// Only drivers/firmware advertising rekey offload support it;
/// mac80211_hwsim replies `-EOPNOTSUPP`.
#[derive(Debug)]
pub struct Nl80211RekeyOffload;

impl Nl80211RekeyOffload {
    /// Start building a `NL80211_CMD_SET_REKEY_OFFLOAD` request for
    /// `if_index`.
    #[allow(clippy::new_ret_no_self)]
    pub fn new(if_index: u32) -> Nl80211RekeyOffloadRequestBuilder {
        Nl80211RekeyOffloadRequestBuilder {
            if_index,
            kek: Vec::new(),
            kck: Vec::new(),
            replay_ctr: Vec::new(),
            akm: Nl80211AkmSuite::Sae,
        }
    }
}

/// Builder for the attributes of a `NL80211_CMD_SET_REKEY_OFFLOAD` request.
#[derive(Debug)]
pub struct Nl80211RekeyOffloadRequestBuilder {
    if_index: u32,
    kek: Vec<u8>,
    kck: Vec<u8>,
    replay_ctr: Vec<u8>,
    akm: Nl80211AkmSuite,
}

impl Nl80211RekeyOffloadRequestBuilder {
    /// Key Encryption Key (16-32 bytes depending on AKM).
    pub fn kek(mut self, kek: Vec<u8>) -> Self {
        self.kek = kek;
        self
    }

    /// Key Confirmation Key (16-24 bytes depending on AKM).
    pub fn kck(mut self, kck: Vec<u8>) -> Self {
        self.kck = kck;
        self
    }

    /// Replay counter (8 bytes).
    pub fn replay_ctr(mut self, replay_ctr: [u8; 8]) -> Self {
        self.replay_ctr = replay_ctr.to_vec();
        self
    }

    /// AKM suite, e.g. [`Nl80211AkmSuite::Sae`].
    pub fn akm(mut self, akm: Nl80211AkmSuite) -> Self {
        self.akm = akm;
        self
    }

    /// Build the attribute list for a `NL80211_CMD_SET_REKEY_OFFLOAD`
    /// request.
    pub fn build(self) -> Vec<Nl80211Attr> {
        // `Nl80211AkmSuite` stores the 802.11 element byte-order; the
        // netlink `NL80211_REKEY_DATA_AKM` attribute expects the kernel's
        // u32 (OUI in the high bytes), so swap.
        let akm = u32::from(self.akm).swap_bytes();
        vec![
            Nl80211Attr::IfIndex(self.if_index),
            Nl80211Attr::RekeyData(vec![
                Nl80211RekeyData::Kek(self.kek),
                Nl80211RekeyData::Kck(self.kck),
                Nl80211RekeyData::ReplayCtr(self.replay_ctr),
                Nl80211RekeyData::Akm(akm),
            ]),
        ]
    }
}

/// Sends a `NL80211_CMD_SET_REKEY_OFFLOAD` request.
pub struct Nl80211RekeyOffloadRequest {
    handle: Nl80211Handle,
    attributes: Vec<Nl80211Attr>,
}

impl Nl80211RekeyOffloadRequest {
    pub(crate) fn new(
        handle: Nl80211Handle,
        attributes: Vec<Nl80211Attr>,
    ) -> Self {
        Nl80211RekeyOffloadRequest { handle, attributes }
    }

    /// Send the `NL80211_CMD_SET_REKEY_OFFLOAD` request.
    ///
    /// A successful return only means the request was accepted by the
    /// driver; unsupported drivers reply with a netlink error.
    pub async fn execute(
        self,
    ) -> impl TryStream<Ok = GenlMessage<Nl80211Message>, Error = Nl80211Error>
    {
        let Nl80211RekeyOffloadRequest {
            mut handle,
            attributes,
        } = self;
        let nl80211_msg = Nl80211Message {
            cmd: Nl80211Command::SetRekeyOffload,
            attributes,
        };
        nl80211_execute(&mut handle, nl80211_msg, NLM_F_REQUEST | NLM_F_ACK)
            .await
    }
}
