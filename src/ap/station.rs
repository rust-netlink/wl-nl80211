// SPDX-License-Identifier: MIT

use futures::TryStream;
use netlink_packet_core::{NLM_F_ACK, NLM_F_REQUEST};
use netlink_packet_generic::GenlMessage;

use crate::{
    Nl80211Attr, Nl80211AttrsBuilder, Nl80211Command, Nl80211Error,
    Nl80211Handle, Nl80211Message, Nl80211StationFlagUpdate, nl80211_execute,
};

macro_rules! station_builder {
    ($name:ident, $req:ident, $cmd:expr, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug)]
        pub struct $name;

        impl $name {
            /// Start building the request for `if_index` and station `mac`.
            pub fn new(
                if_index: u32,
                mac: [u8; 6],
            ) -> Nl80211AttrsBuilder<Self> {
                Nl80211AttrsBuilder::<Self>::new()
                    .if_index(if_index)
                    .replace(Nl80211Attr::Mac(mac))
            }
        }

        pub struct $req {
            handle: Nl80211Handle,
            attributes: Vec<Nl80211Attr>,
        }

        impl $req {
            pub(crate) fn new(
                handle: Nl80211Handle,
                attributes: Vec<Nl80211Attr>,
            ) -> Self {
                Self { handle, attributes }
            }

            pub async fn execute(
                self,
            ) -> impl TryStream<
                Ok = GenlMessage<Nl80211Message>,
                Error = Nl80211Error,
            > {
                let Self {
                    mut handle,
                    attributes,
                } = self;
                nl80211_execute(
                    &mut handle,
                    Nl80211Message {
                        cmd: $cmd,
                        attributes,
                    },
                    NLM_F_REQUEST | NLM_F_ACK,
                )
                .await
            }
        }
    };
}

macro_rules! station_params_builder {
    ($name:ident) => {
        impl Nl80211AttrsBuilder<$name> {
            /// Association ID (`NL80211_ATTR_STA_AID`).
            pub fn aid(self, aid: u16) -> Self {
                self.replace(Nl80211Attr::StaAid(aid))
            }

            /// Listen interval (`NL80211_ATTR_STA_LISTEN_INTERVAL`).
            pub fn listen_interval(self, interval: u16) -> Self {
                self.replace(Nl80211Attr::StaListenInterval(interval))
            }

            /// Supported rates (`NL80211_ATTR_STA_SUPPORTED_RATES`).
            pub fn supported_rates(self, rates: Vec<u8>) -> Self {
                self.replace(Nl80211Attr::StaSupportedRates(rates))
            }

            /// Station capabilities (`NL80211_ATTR_STA_CAPABILITY`).
            pub fn capability(self, capability: u16) -> Self {
                self.replace(Nl80211Attr::StaCapability(capability))
            }

            /// Station flags mask/set (`NL80211_ATTR_STA_FLAGS2`).
            pub fn flags2(self, update: Nl80211StationFlagUpdate) -> Self {
                self.replace(Nl80211Attr::StaFlags2(update))
            }

            /// Extended capabilities (`NL80211_ATTR_STA_EXT_CAPABILITY`).
            pub fn ext_capability(self, capabilities: Vec<u8>) -> Self {
                self.replace(Nl80211Attr::StaExtCapability(capabilities))
            }

            /// Supported channels (`NL80211_ATTR_STA_SUPPORTED_CHANNELS`).
            pub fn supported_channels(self, channels: Vec<u8>) -> Self {
                self.replace(Nl80211Attr::StaSupportedChannels(channels))
            }

            /// Supported operating classes
            /// (`NL80211_ATTR_STA_SUPPORTED_OPER_CLASSES`).
            pub fn supported_oper_classes(self, classes: Vec<u8>) -> Self {
                self.replace(Nl80211Attr::StaSupportedOperClasses(classes))
            }
        }
    };
}

station_builder!(
    Nl80211StationAdd,
    Nl80211StationAddRequest,
    Nl80211Command::NewStation,
    "Builder for `NL80211_CMD_NEW_STATION`."
);
station_builder!(
    Nl80211StationSet,
    Nl80211StationSetRequest,
    Nl80211Command::SetStation,
    "Builder for `NL80211_CMD_SET_STATION`."
);
station_builder!(
    Nl80211StationDel,
    Nl80211StationDelRequest,
    Nl80211Command::DelStation,
    "Builder for `NL80211_CMD_DEL_STATION`."
);

station_params_builder!(Nl80211StationAdd);
station_params_builder!(Nl80211StationSet);
