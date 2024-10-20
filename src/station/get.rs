// SPDX-License-Identifier: MIT

use futures::TryStream;
use netlink_packet_core::{NLM_F_DUMP, NLM_F_REQUEST};
use netlink_packet_generic::GenlMessage;

use crate::{
    nl80211_execute, Nl80211Attr, Nl80211Command, Nl80211Error, Nl80211Handle,
    Nl80211Message,
};

const ETH_ALEN: usize = 6;

pub struct Nl80211StationGetRequest {
    handle: Nl80211Handle,
    if_index: u32,
    mac_address: Option<[u8; ETH_ALEN]>,
}

impl Nl80211StationGetRequest {
    pub(crate) fn new(
        handle: Nl80211Handle,
        if_index: u32,
        mac_address: Option<[u8; ETH_ALEN]>,
    ) -> Self {
        Nl80211StationGetRequest {
            handle,
            if_index,
            mac_address,
        }
    }

    pub async fn execute(
        self,
    ) -> impl TryStream<Ok = GenlMessage<Nl80211Message>, Error = Nl80211Error>
    {
        let Nl80211StationGetRequest {
            mut handle,
            if_index,
            mac_address,
        } = self;

        let mut attributes = vec![Nl80211Attr::IfIndex(if_index)];
        if let Some(arr) = mac_address {
            attributes.push(Nl80211Attr::Mac(arr))
        }

        let nl80211_msg = Nl80211Message {
            cmd: Nl80211Command::GetStation,
            attributes,
        };

        let flags = NLM_F_REQUEST | NLM_F_DUMP;

        nl80211_execute(&mut handle, nl80211_msg, flags).await
    }
}
