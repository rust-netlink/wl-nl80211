// SPDX-License-Identifier: MIT

use futures::TryStream;
use netlink_packet_core::{NLM_F_ACK, NLM_F_REQUEST};
use netlink_packet_generic::GenlMessage;

use crate::{
    nl80211_execute, Nl80211Attr, Nl80211AttrsBuilder, Nl80211AuthType,
    Nl80211Command, Nl80211Error, Nl80211Handle, Nl80211Message,
};

/// Helper to build the attribute list for a `NL80211_CMD_AUTHENTICATE`
/// request.
///
/// This is the SME-in-userspace path: the caller performs the authentication
/// (e.g. SAE) and hands the result to the kernel. For WPA3-Personal the
/// commit / confirm bodies are delivered via
/// [`auth_data`](Self::auth_data) with [`auth_type`](Self::auth_type) set to
/// [`Nl80211AuthType::Sae`]; for open (no-encryption) networks use
/// [`Nl80211AuthType::OpenSystem`] without auth data.
#[derive(Debug)]
pub struct Nl80211Authenticate;

impl Nl80211Authenticate {
    /// Start building an authenticate request for the interface `if_index`.
    pub fn new(if_index: u32) -> Nl80211AttrsBuilder<Self> {
        Nl80211AttrsBuilder::<Self>::new().if_index(if_index)
    }
}

impl Nl80211AttrsBuilder<Nl80211Authenticate> {
    /// BSSID of the AP to authenticate with.
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

    /// Authentication data, e.g. the SAE commit or confirm body
    /// (`transaction || status || body`).
    pub fn auth_data(self, auth_data: Vec<u8>) -> Self {
        self.replace(Nl80211Attr::AuthData(auth_data))
    }
}

pub struct Nl80211AuthenticateRequest {
    handle: Nl80211Handle,
    attributes: Vec<Nl80211Attr>,
}

impl Nl80211AuthenticateRequest {
    pub(crate) fn new(
        handle: Nl80211Handle,
        attributes: Vec<Nl80211Attr>,
    ) -> Self {
        Nl80211AuthenticateRequest { handle, attributes }
    }

    /// Send the `NL80211_CMD_AUTHENTICATE` request.
    ///
    /// A successful return only means the request was accepted by the kernel;
    /// the authentication result is delivered asynchronously as a
    /// `NL80211_CMD_AUTHENTICATE` event on the multicast group.
    pub async fn execute(
        self,
    ) -> impl TryStream<Ok = GenlMessage<Nl80211Message>, Error = Nl80211Error>
    {
        let Nl80211AuthenticateRequest {
            mut handle,
            attributes,
        } = self;

        let nl80211_msg = Nl80211Message {
            cmd: Nl80211Command::Authenticate,
            attributes,
        };
        let flags = NLM_F_REQUEST | NLM_F_ACK;

        nl80211_execute(&mut handle, nl80211_msg, flags).await
    }
}
