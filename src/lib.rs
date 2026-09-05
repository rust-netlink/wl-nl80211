// SPDX-License-Identifier: MIT

mod attr;
mod band;
mod builder;
mod channel;
mod command;
mod connect;
mod connection;
mod cqm;
mod eapol;
mod element;
mod error;
mod event;
mod event_status;
mod ext_cap;
mod feature;
mod frame;
mod handle;
mod iface;
mod key;
mod key_request;
mod mac;
mod macros;
mod message;
mod mlo;
mod rekey;
mod rekey_request;
mod scan;
mod station;
mod stats;
mod survey;
mod wifi4;
mod wifi5;
mod wifi6;
mod wifi7;
mod wiphy;
mod wowlan_request;

// test data are using hard coded little endian byte order, not for big-endian
#[cfg(not(target_endian = "big"))]
#[cfg(test)]
mod tests;

pub(crate) mod bytes;

// reexport public API of packet_core and packet_generic
pub use netlink_packet_core as packet_core;
pub use netlink_packet_generic as packet_generic;

pub use self::attr::Nl80211Attr;
pub use self::band::Ieee80211OperatingClass;
pub use self::builder::Nl80211AttrsBuilder;
pub use self::channel::Nl80211ChannelWidth;
pub use self::command::Nl80211Command;
pub use self::connect::{
    Nl80211Associate, Nl80211AssociateRequest, Nl80211AuthType,
    Nl80211Authenticate, Nl80211AuthenticateRequest, Nl80211Connect,
    Nl80211ConnectRequest, Nl80211ConnectionHandle, Nl80211ControlPortFrame,
    Nl80211ControlPortFrameRequest, Nl80211DelPmkRequest,
    Nl80211DelPmksaRequest, Nl80211Disconnect, Nl80211DisconnectRequest,
    Nl80211ExternalAuth, Nl80211ExternalAuthAction, Nl80211ExternalAuthRequest,
    Nl80211FlushPmksaRequest, Nl80211Frame, Nl80211FrameRequest, Nl80211Pmk,
    Nl80211Pmksa, Nl80211RegisterFrame, Nl80211RegisterFrameRequest,
    Nl80211SetPmkRequest, Nl80211SetPmksaRequest, Nl80211UseMfp,
    Nl80211WpaVersions,
};
#[cfg(feature = "tokio_socket")]
pub use self::connection::new_connection;
pub use self::connection::new_connection_with_socket;
#[cfg(feature = "tokio_socket")]
pub use self::connection::new_multicast_connection;
pub use self::connection::new_multicast_connection_with_socket;
pub use self::connection::Nl80211MulticastGroup;
pub use self::cqm::{
    Nl80211Cqm, Nl80211CqmAttr, Nl80211CqmRequest, Nl80211CqmRssiEvent,
    Nl80211CqmRssiThresholdEvent,
};
pub use self::eapol::{
    Ieee80211EapolEapFrame, Ieee80211EapolFrame, Ieee80211EapolKeyFrame,
};
pub use self::element::{
    Ieee80211AkmSuite, Ieee80211CipherSuite, Ieee80211Element,
    Ieee80211ElementCountryEnvironment, Ieee80211ElementCountryTriplet,
    Ieee80211ElementRsn, Ieee80211ElementRsnExt, Ieee80211Elements,
    Ieee80211Pmkid, Ieee80211RateAndSelector, Ieee80211RsnCapbilities,
    Ieee80211RsnExtCapbilities,
};
pub use self::error::Nl80211Error;
pub use self::event::{
    Nl80211Event, Nl80211EventAssociated, Nl80211EventAuthenticated,
};
pub use self::event_status::{Ieee80211ReasonCode, Ieee80211StatusCode};
pub use self::ext_cap::{
    Ieee80211ExtendedCapability, Nl80211IfTypeExtCapa, Nl80211IfTypeExtCapas,
};
pub use self::feature::{Nl80211ExtFeature, Nl80211Features};
pub use self::frame::{
    Ieee80211ActionFrame, Ieee80211ActionFrameBtmRequest,
    Ieee80211ActionFrameBtmResponse, Ieee80211ActionFrameNeighborReportRequest,
    Ieee80211ActionFrameNeighborReportResponse, Ieee80211ActionFrameOther,
    Ieee80211AssocRespFrame, Ieee80211AuthAlgorithm, Ieee80211AuthFrame,
    Ieee80211AuthFrameEppke, Ieee80211AuthFrameFastBssTransition,
    Ieee80211AuthFrameFilsPublicKey, Ieee80211AuthFrameFilsSharedKey,
    Ieee80211AuthFrameFilsSharedKeyPfs, Ieee80211AuthFrameIeee8021x,
    Ieee80211AuthFrameLeap, Ieee80211AuthFrameOpenSystem,
    Ieee80211AuthFrameOther, Ieee80211AuthFramePasn, Ieee80211AuthFrameSae,
    Ieee80211AuthFrameSharedKey, Ieee80211AuthFrameVendorSpecific,
    Ieee80211BtmCandidate, Ieee80211BtmRequest, Ieee80211BtmResponse,
    Ieee80211CapabilityInfo, Ieee80211Frame, Ieee80211FrameType,
    Ieee80211NeighborReportEntry, Ieee80211NeighborReportRequest,
    Ieee80211NeighborReportResponse, Nl80211IfaceFrameType,
};
pub use self::handle::Nl80211Handle;
pub use self::iface::{
    Nl80211IfaceComb, Nl80211IfaceCombAttribute, Nl80211IfaceCombLimit,
    Nl80211IfaceCombLimitAttribute, Nl80211Interface,
    Nl80211InterfaceDeleteRequest, Nl80211InterfaceGetRequest,
    Nl80211InterfaceHandle, Nl80211InterfaceNewRequest,
    Nl80211InterfaceSetRequest, Nl80211InterfaceType,
    Nl80211InterfaceVendorRequest, Nl80211NewInterface, Nl80211Vendor,
};
pub use self::key::{Nl80211KeyAttr, Nl80211KeyDefaultType, Nl80211KeyType};
pub use self::key_request::{Nl80211Key, Nl80211KeyRequest};
pub use self::message::Nl80211Message;
pub use self::mlo::Nl80211MloLink;
pub use self::rekey::Nl80211RekeyData;
pub use self::rekey_request::{
    Nl80211RekeyOffload, Nl80211RekeyOffloadRequest,
};
pub use self::scan::{
    Nl80211BssInfo, Nl80211BssUseFor, Nl80211Scan, Nl80211ScanFlags,
    Nl80211ScanGetRequest, Nl80211ScanHandle, Nl80211ScanScheduleRequest,
    Nl80211ScanScheduleStopRequest, Nl80211ScanTriggerRequest,
    Nl80211SchedScanMatch, Nl80211SchedScanMatchAttr, Nl80211SchedScanPlan,
    Nl80211SchedScanPlanAttr,
};
pub use self::station::{
    Nl80211EhtGi, Nl80211EhtRuAllocation, Nl80211HeGi, Nl80211HeRuAllocation,
    Nl80211MeshPowerMode, Nl80211PeerLinkState, Nl80211RateInfo,
    Nl80211StationBssParam, Nl80211StationFlagUpdate, Nl80211StationFlags,
    Nl80211StationGetRequest, Nl80211StationHandle, Nl80211StationInfo,
};
pub use self::stats::{
    NestedNl80211TidStats, Nl80211TidStats, Nl80211TransmitQueueStat,
};
pub use self::survey::{
    Nl80211Survey, Nl80211SurveyGetRequest, Nl80211SurveyHandle,
    Nl80211SurveyInfo,
};
pub use self::wifi4::{
    Ieee80211ElementHtCap, Ieee80211HtAMpduPara, Ieee80211HtAselCaps,
    Ieee80211HtCapabilityMask, Ieee80211HtCaps, Ieee80211HtExtendedCap,
    Ieee80211HtMcsInfo, Ieee80211HtTransmitBeamformingCaps,
    Ieee80211HtTxParameter, Nl80211HtWiphyChannelType,
};
pub use self::wifi5::{
    Ieee80211ElementVhtCap, Ieee80211VhtCapInfo, Ieee80211VhtCapability,
    Ieee80211VhtMcsInfo,
};
pub use self::wifi6::{
    Ieee80211ElementHeCap, Ieee80211He6GhzCapa, Ieee80211HeMacCapInfo,
    Ieee80211HeMcsNssSupp, Ieee80211HePhyCapInfo, Ieee80211HePpeThreshold,
};
pub use self::wifi7::{
    Ieee80211EhtMacCapInfo, Ieee80211EhtMcsNssSupp,
    Ieee80211EhtMcsNssSuppMoreThan20Mhz, Ieee80211EhtMcsNssSuppOnly20Mhz,
    Ieee80211EhtPhyCapInfo, Ieee80211EhtPpeThres,
};
pub use self::wiphy::{
    Nl80211Band, Nl80211BandIftypeData, Nl80211BandInfo, Nl80211BandType,
    Nl80211BandTypes, Nl80211Channel, Nl80211ChannelSwitchRequest,
    Nl80211Frequency, Nl80211FrequencyInfo, Nl80211IfMode, Nl80211Rate,
    Nl80211WiphyGetRequest, Nl80211WiphyHandle, Nl80211WowlanTcpTriggerSupport,
    Nl80211WowlanTriggerPatternSupport, Nl80211WowlanTriggersSupport,
    Nl80211WowlanWakeup,
};
pub use self::wowlan_request::{Nl80211Wowlan, Nl80211WowlanRequest};

pub(crate) use self::feature::Nl80211ExtFeatures;
pub(crate) use self::handle::nl80211_execute;
pub(crate) use self::iface::Nl80211InterfaceTypes;
