// SPDX-License-Identifier: MIT

use futures::TryStream;
use netlink_packet_core::{NLM_F_DUMP, NLM_F_REQUEST};
use netlink_packet_generic::GenlMessage;

use crate::{
    nl80211_execute, Nl80211Attr, Nl80211Command, Nl80211Error, Nl80211Handle,
    Nl80211Message,
};

pub struct Nl80211WiphyGetRequest {
    handle: Nl80211Handle,
    filter: Option<Nl80211Attr>,
}

impl Nl80211WiphyGetRequest {
    pub(crate) fn new(handle: Nl80211Handle) -> Self {
        Nl80211WiphyGetRequest {
            handle,
            filter: None,
        }
    }

    /// Filter the dump to the wiphy with this wiphy index
    /// (`NL80211_ATTR_WIPHY`).
    ///
    /// Replaces any previously set filter.
    pub fn wiphy_index(mut self, wiphy_index: u32) -> Self {
        self.filter = Some(Nl80211Attr::Wiphy(wiphy_index));
        self
    }

    /// Filter the dump to the wiphy owning the interface with this interface
    /// index (`NL80211_ATTR_IFINDEX`).
    ///
    /// Replaces any previously set filter.
    pub fn if_index(mut self, if_index: u32) -> Self {
        self.filter = Some(Nl80211Attr::IfIndex(if_index));
        self
    }

    /// Filter the dump to the wiphy owning the wireless device with this wdev
    /// identifier (`NL80211_ATTR_WDEV`).
    ///
    /// Replaces any previously set filter.
    pub fn wdev(mut self, wdev: u64) -> Self {
        self.filter = Some(Nl80211Attr::Wdev(wdev));
        self
    }

    pub async fn execute(
        self,
    ) -> impl TryStream<Ok = GenlMessage<Nl80211Message>, Error = Nl80211Error>
    {
        let Nl80211WiphyGetRequest { mut handle, filter } = self;

        let mut attributes = vec![Nl80211Attr::SplitWiphyDump];

        if let Some(f) = filter {
            attributes.push(f);
        }

        let nl80211_msg = Nl80211Message {
            cmd: Nl80211Command::GetWiphy,
            attributes,
        };

        let flags = NLM_F_REQUEST | NLM_F_DUMP;

        nl80211_execute(&mut handle, nl80211_msg, flags).await
    }
}
