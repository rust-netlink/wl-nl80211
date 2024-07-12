// SPDX-License-Identifier: MIT

mod attr;
mod channel;
mod connection;
mod error;
mod ext_cap;
mod feature;
mod frame_type;
mod handle;
mod iface;
mod macros;
mod message;
mod mlo;
mod scan;
mod station;
mod stats;
mod wifi4;
mod wifi5;
mod wifi6;
mod wifi7;
mod wiphy;

pub(crate) mod bytes;

pub use self::attr::Nl80211Attr;
pub use self::channel::Nl80211ChannelWidth;
#[cfg(feature = "tokio_socket")]
pub use self::connection::new_connection;
pub use self::connection::new_connection_with_socket;
pub use self::error::Nl80211Error;
pub use self::ext_cap::{
    Nl80211ExtendedCapability, Nl80211IfTypeExtCapa, Nl80211IfTypeExtCapas,
};
pub use self::feature::{Nl80211ExtFeature, Nl80211Features};
pub use self::frame_type::{Nl80211FrameType, Nl80211IfaceFrameType};
pub use self::handle::Nl80211Handle;
pub use self::iface::{
    Nl80211IfaceComb, Nl80211IfaceCombAttribute, Nl80211IfaceCombLimit,
    Nl80211IfaceCombLimitAttribute, Nl80211InterfaceGetRequest,
    Nl80211InterfaceHandle, Nl80211InterfaceType,
};
pub use self::message::{Nl80211Cmd, Nl80211Message};
pub use self::mlo::Nl80211MloLink;
pub use self::scan::{
    Nl80211BssInfo, Nl80211InformationElements, Nl80211ScanGetRequest,
    Nl80211ScanHandle,
};
pub use self::station::{
    Nl80211StationGetRequest, Nl80211StationHandle, Nl80211StationInfo,
};
pub use self::stats::{
    NestedNl80211TidStats, Nl80211TidStats, Nl80211TransmitQueueStat,
};
pub use self::wifi4::{
    Nl80211HtCapabilityMask, Nl80211HtCaps, Nl80211HtMcsInfo,
    Nl80211HtWiphyChannelType,
};
pub use self::wifi5::{
    Nl80211VhtCapInfo, Nl80211VhtCapability, Nl80211VhtMcsInfo,
};
pub use self::wifi6::{
    Nl80211He6GhzCapa, Nl80211HeMacCapInfo, Nl80211HeMcsNssSupp,
    Nl80211HePhyCapInfo, Nl80211HePpeThreshold,
};
pub use self::wifi7::{
    Nl80211EhtMacCapInfo, Nl80211EhtMcsNssSupp,
    Nl80211EhtMcsNssSuppMoreThan20Mhz, Nl80211EhtMcsNssSuppOnly20Mhz,
    Nl80211EhtPhyCapInfo, Nl80211EhtPpeThres,
};
pub use self::wiphy::{
    Nl80211Band, Nl80211BandInfo, Nl80211BandType, Nl80211BandTypes,
    Nl80211CipherSuit, Nl80211Command, Nl80211Frequency, Nl80211FrequencyInfo,
    Nl80211IfMode, Nl80211WiphyGetRequest, Nl80211WiphyHandle,
    Nl80211WowlanTcpTrigerSupport, Nl80211WowlanTrigerPatternSupport,
    Nl80211WowlanTrigersSupport,
};

pub(crate) use self::feature::Nl80211ExtFeatures;
pub(crate) use self::handle::nl80211_execute;
pub(crate) use self::iface::Nl80211InterfaceTypes;
