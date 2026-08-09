// SPDX-License-Identifier: MIT

use futures::TryStream;
use netlink_packet_core::{NLM_F_ACK, NLM_F_REQUEST};
use netlink_packet_generic::GenlMessage;

use crate::{
    nl80211_execute, Nl80211Attr, Nl80211Command, Nl80211Error, Nl80211Handle,
    Nl80211Message, Nl80211WowlanTriggersSupport,
};

/// Helper to build the attribute list for a `NL80211_CMD_SET_WOWLAN`
/// request, arming WoWLAN triggers so the device can wake the host while
/// it is suspended (e.g. on a GTK rekey failure).
///
/// Only drivers advertising WoWLAN support accept it; mac80211_hwsim
/// replies `-EOPNOTSUPP`.
#[derive(Debug)]
pub struct Nl80211Wowlan;

impl Nl80211Wowlan {
    /// Start building a `NL80211_CMD_SET_WOWLAN` request for `if_index`.
    #[allow(clippy::new_ret_no_self)]
    pub fn new(if_index: u32) -> Nl80211WowlanRequestBuilder {
        Nl80211WowlanRequestBuilder {
            if_index,
            triggers: Vec::new(),
        }
    }
}

/// Builder for the attributes of a `NL80211_CMD_SET_WOWLAN` request.
#[derive(Debug)]
pub struct Nl80211WowlanRequestBuilder {
    if_index: u32,
    triggers: Vec<Nl80211WowlanTriggersSupport>,
}

impl Nl80211WowlanRequestBuilder {
    /// The WoWLAN triggers to arm, e.g.
    /// `[Nl80211WowlanTriggersSupport::Disconnect,
    /// Nl80211WowlanTriggersSupport::GtkRekeyFailure]`.
    pub fn triggers(
        mut self,
        triggers: Vec<Nl80211WowlanTriggersSupport>,
    ) -> Self {
        self.triggers = triggers;
        self
    }

    /// Build the attribute list for a `NL80211_CMD_SET_WOWLAN` request.
    pub fn build(self) -> Vec<Nl80211Attr> {
        vec![
            Nl80211Attr::IfIndex(self.if_index),
            Nl80211Attr::WowlanTriggers(self.triggers),
        ]
    }
}

/// Sends a `NL80211_CMD_SET_WOWLAN` request.
pub struct Nl80211WowlanRequest {
    handle: Nl80211Handle,
    attributes: Vec<Nl80211Attr>,
}

impl Nl80211WowlanRequest {
    pub(crate) fn new(
        handle: Nl80211Handle,
        attributes: Vec<Nl80211Attr>,
    ) -> Self {
        Nl80211WowlanRequest { handle, attributes }
    }

    /// Send the `NL80211_CMD_SET_WOWLAN` request.
    ///
    /// A successful return only means the request was accepted by the
    /// driver; unsupported drivers reply with a netlink error.
    pub async fn execute(
        self,
    ) -> impl TryStream<Ok = GenlMessage<Nl80211Message>, Error = Nl80211Error>
    {
        let Nl80211WowlanRequest {
            mut handle,
            attributes,
        } = self;
        let nl80211_msg = Nl80211Message {
            cmd: Nl80211Command::SetWowlan,
            attributes,
        };
        nl80211_execute(&mut handle, nl80211_msg, NLM_F_REQUEST | NLM_F_ACK)
            .await
    }
}
