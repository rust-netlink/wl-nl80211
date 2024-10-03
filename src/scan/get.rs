// SPDX-License-Identifier: MIT

use futures::TryStream;
use netlink_packet_generic::GenlMessage;

use crate::{
    nl80211_execute, Nl80211Attr, Nl80211Command, Nl80211Error, Nl80211Handle,
    Nl80211Message,
};

pub struct Nl80211ScanGetRequest {
    handle: Nl80211Handle,
    if_index: u32,
}

impl Nl80211ScanGetRequest {
    pub(crate) fn new(handle: Nl80211Handle, if_index: u32) -> Self {
        Nl80211ScanGetRequest { handle, if_index }
    }

    pub async fn execute(
        self,
    ) -> impl TryStream<Ok = GenlMessage<Nl80211Message>, Error = Nl80211Error>
    {
        let Nl80211ScanGetRequest {
            mut handle,
            if_index,
        } = self;

        let attributes = vec![Nl80211Attr::IfIndex(if_index)];
        let nl80211_msg = Nl80211Message {
            cmd: Nl80211Command::GetScan,
            attributes,
        };

        nl80211_execute(&mut handle, nl80211_msg).await
    }
}
