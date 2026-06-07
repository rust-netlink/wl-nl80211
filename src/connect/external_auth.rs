// SPDX-License-Identifier: MIT

use futures::TryStream;
use netlink_packet_core::{NLM_F_ACK, NLM_F_REQUEST};
use netlink_packet_generic::GenlMessage;

use crate::{
    nl80211_execute, Nl80211Attr, Nl80211AttrsBuilder, Nl80211Command,
    Nl80211Error, Nl80211Handle, Nl80211Message,
};

/// Helper to build the attribute list for a `NL80211_CMD_EXTERNAL_AUTH`
/// request, used by userspace to report the result of an externally performed
/// authentication (e.g. SAE) back to the kernel.
///
/// The kernel requires [`ssid`](Nl80211AttrsBuilder::ssid),
/// [`bssid`](Nl80211AttrsBuilder::<Nl80211ExternalAuth>::bssid) and
/// [`status_code`](Nl80211AttrsBuilder::<Nl80211ExternalAuth>::status_code)
/// to be set.
#[derive(Debug)]
pub struct Nl80211ExternalAuth;

impl Nl80211ExternalAuth {
    /// Start building an external-auth result for the interface `if_index`.
    pub fn new(if_index: u32) -> Nl80211AttrsBuilder<Self> {
        Nl80211AttrsBuilder::<Self>::new().if_index(if_index)
    }
}

impl Nl80211AttrsBuilder<Nl80211ExternalAuth> {
    /// BSSID of the AP the authentication was performed with.
    pub fn bssid(self, bssid: [u8; 6]) -> Self {
        self.replace(Nl80211Attr::Bssid(bssid))
    }

    /// IEEE 802.11 status code of the authentication (0 means success).
    pub fn status_code(self, status: u16) -> Self {
        self.replace(Nl80211Attr::StatusCode(status))
    }
}

pub struct Nl80211ExternalAuthRequest {
    handle: Nl80211Handle,
    attributes: Vec<Nl80211Attr>,
}

impl Nl80211ExternalAuthRequest {
    pub(crate) fn new(
        handle: Nl80211Handle,
        attributes: Vec<Nl80211Attr>,
    ) -> Self {
        Nl80211ExternalAuthRequest { handle, attributes }
    }

    /// Send the `NL80211_CMD_EXTERNAL_AUTH` request.
    pub async fn execute(
        self,
    ) -> impl TryStream<Ok = GenlMessage<Nl80211Message>, Error = Nl80211Error>
    {
        let Nl80211ExternalAuthRequest {
            mut handle,
            attributes,
        } = self;

        let nl80211_msg = Nl80211Message {
            cmd: Nl80211Command::ExternalAuth,
            attributes,
        };
        let flags = NLM_F_REQUEST | NLM_F_ACK;

        nl80211_execute(&mut handle, nl80211_msg, flags).await
    }
}
