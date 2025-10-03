// SPDX-License-Identifier: MIT

use crate::handle::nl80211_execute;
use crate::{
    Nl80211Attr, Nl80211Command, Nl80211Error, Nl80211Handle, Nl80211Message,
};
use futures::TryStream;
use netlink_packet_core::NLM_F_REQUEST;
use netlink_packet_generic::GenlMessage;

/// Request for creating a new 802.11 interface.
pub struct Nl80211InterfaceNewRequest {
    handle: Nl80211Handle,
    attributes: Vec<Nl80211Attr>,
}

impl Nl80211InterfaceNewRequest {
    /// Create a new Add request.
    ///
    /// See <https://github.com/torvalds/linux/blob/v6.17/include/uapi/linux/nl80211.h#L374> for
    /// required attributes.
    pub fn new(handle: Nl80211Handle, attributes: Vec<Nl80211Attr>) -> Self {
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
                cmd: Nl80211Command::NewInterface,
                attributes,
            },
            NLM_F_REQUEST,
        )
        .await
    }
}
