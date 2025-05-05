// SPDX-License-Identifier: MIT

use futures::TryStream;
use netlink_packet_core::{NLM_F_ACK, NLM_F_REQUEST};
use netlink_packet_generic::GenlMessage;

use crate::{
    nl80211_execute, Nl80211Attr, Nl80211Command, Nl80211Error, Nl80211Handle,
    Nl80211Message,
};

pub struct Nl80211InterfaceSetRequest {
    handle: Nl80211Handle,
    attributes: Vec<Nl80211Attr>,
}

impl Nl80211InterfaceSetRequest {
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
        let Nl80211InterfaceSetRequest {
            mut handle,
            attributes,
        } = self;

        let nl80211_msg = Nl80211Message {
            cmd: Nl80211Command::SetInterface,
            // TODO: Should this be open to every attribute or restricted to
            // Interface ATTR?
            attributes: dbg!(attributes),
        };
        // TODO: is the in iw dev set
        // I don't understand the correct seting of flags yet. In case of set
        // `iw` does not set any flag, but here NLM_F_REQUEST is always
        // set. Curentliy infreadead.org libnl documentation website is
        // down. These are the same flags as in scan.rs
        let flags = NLM_F_REQUEST | NLM_F_ACK;

        nl80211_execute(&mut handle, nl80211_msg, flags).await
    }
}
