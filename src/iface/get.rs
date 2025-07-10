// SPDX-License-Identifier: MIT

use futures::TryStream;
use netlink_packet_core::{NLM_F_DUMP, NLM_F_REQUEST};
use netlink_packet_generic::GenlMessage;

use crate::{
    nl80211_execute, Nl80211Attr, Nl80211Command, Nl80211Error, Nl80211Handle,
    Nl80211Message,
};

pub struct Nl80211InterfaceGetRequest {
    handle: Nl80211Handle,
    attributes: Vec<Nl80211Attr>,
}

impl Nl80211InterfaceGetRequest {
    pub(crate) fn new(
        handle: Nl80211Handle,
        attributes: Vec<Nl80211Attr>,
    ) -> Self {
        Nl80211InterfaceGetRequest { handle, attributes }
    }

    pub async fn execute(
        self,
    ) -> impl TryStream<Ok = GenlMessage<Nl80211Message>, Error = Nl80211Error>
    {
        let Nl80211InterfaceGetRequest {
            mut handle,
            attributes,
        } = self;

        let mut flags = NLM_F_REQUEST;
        if attributes.is_empty() {
            flags |= NLM_F_DUMP;
        }

        let nl80211_msg = Nl80211Message {
            cmd: Nl80211Command::GetInterface,
            attributes,
        };

        nl80211_execute(&mut handle, nl80211_msg, flags).await
    }
}
