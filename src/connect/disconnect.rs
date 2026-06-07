// SPDX-License-Identifier: MIT

use futures::TryStream;
use netlink_packet_core::{NLM_F_ACK, NLM_F_REQUEST};
use netlink_packet_generic::GenlMessage;

use crate::{
    nl80211_execute, Nl80211Attr, Nl80211AttrsBuilder, Nl80211Command,
    Nl80211Error, Nl80211Handle, Nl80211Message,
};

/// IEEE 802.11 reason code "Deauthenticated because sending STA is leaving"
/// (3), the default used when disconnecting.
const WLAN_REASON_DEAUTH_LEAVING: u16 = 3;

/// Helper to build the attribute list for a `NL80211_CMD_DISCONNECT` request.
#[derive(Debug)]
pub struct Nl80211Disconnect;

impl Nl80211Disconnect {
    /// Start building a disconnect request for the interface `if_index`.
    /// Defaults the reason code to "STA is leaving".
    pub fn new(if_index: u32) -> Nl80211AttrsBuilder<Self> {
        Nl80211AttrsBuilder::<Self>::new()
            .if_index(if_index)
            .reason_code(WLAN_REASON_DEAUTH_LEAVING)
    }
}

impl Nl80211AttrsBuilder<Nl80211Disconnect> {
    /// IEEE 802.11 reason code to report to the AP.
    pub fn reason_code(self, reason: u16) -> Self {
        self.replace(Nl80211Attr::ReasonCode(reason))
    }
}

pub struct Nl80211DisconnectRequest {
    handle: Nl80211Handle,
    attributes: Vec<Nl80211Attr>,
}

impl Nl80211DisconnectRequest {
    pub(crate) fn new(
        handle: Nl80211Handle,
        attributes: Vec<Nl80211Attr>,
    ) -> Self {
        Nl80211DisconnectRequest { handle, attributes }
    }

    /// Send the `NL80211_CMD_DISCONNECT` request.
    pub async fn execute(
        self,
    ) -> impl TryStream<Ok = GenlMessage<Nl80211Message>, Error = Nl80211Error>
    {
        let Nl80211DisconnectRequest {
            mut handle,
            attributes,
        } = self;

        let nl80211_msg = Nl80211Message {
            cmd: Nl80211Command::Disconnect,
            attributes,
        };
        let flags = NLM_F_REQUEST | NLM_F_ACK;

        nl80211_execute(&mut handle, nl80211_msg, flags).await
    }
}
