// SPDX-License-Identifier: MIT

const NL80211_CMD_GET_WIPHY: u8 = 1;
const NL80211_CMD_SET_WIPHY: u8 = 2;
const NL80211_CMD_NEW_WIPHY: u8 = 3;
const NL80211_CMD_DEL_WIPHY: u8 = 4;
const NL80211_CMD_GET_INTERFACE: u8 = 5;
const NL80211_CMD_SET_INTERFACE: u8 = 6;
const NL80211_CMD_NEW_INTERFACE: u8 = 7;
const NL80211_CMD_DEL_INTERFACE: u8 = 8;
const NL80211_CMD_GET_KEY: u8 = 9;
const NL80211_CMD_SET_KEY: u8 = 10;
const NL80211_CMD_NEW_KEY: u8 = 11;
const NL80211_CMD_DEL_KEY: u8 = 12;
const NL80211_CMD_GET_BEACON: u8 = 13;
const NL80211_CMD_SET_BEACON: u8 = 14;
const NL80211_CMD_START_AP: u8 = 15;
const NL80211_CMD_STOP_AP: u8 = 16;
const NL80211_CMD_GET_STATION: u8 = 17;
const NL80211_CMD_SET_STATION: u8 = 18;
const NL80211_CMD_NEW_STATION: u8 = 19;
const NL80211_CMD_DEL_STATION: u8 = 20;
const NL80211_CMD_GET_MPATH: u8 = 21;
const NL80211_CMD_SET_MPATH: u8 = 22;
const NL80211_CMD_NEW_MPATH: u8 = 23;
const NL80211_CMD_DEL_MPATH: u8 = 24;
const NL80211_CMD_SET_BSS: u8 = 25;
const NL80211_CMD_SET_REG: u8 = 26;
const NL80211_CMD_REQ_SET_REG: u8 = 27;
const NL80211_CMD_GET_MESH_CONFIG: u8 = 28;
const NL80211_CMD_SET_MESH_CONFIG: u8 = 29;
const NL80211_CMD_SET_MGMT_EXTRA_IE: u8 = 30;
const NL80211_CMD_GET_REG: u8 = 31;
const NL80211_CMD_GET_SCAN: u8 = 32;
const NL80211_CMD_TRIGGER_SCAN: u8 = 33;
const NL80211_CMD_NEW_SCAN_RESULTS: u8 = 34;
const NL80211_CMD_SCAN_ABORTED: u8 = 35;
const NL80211_CMD_REG_CHANGE: u8 = 36;
const NL80211_CMD_AUTHENTICATE: u8 = 37;
const NL80211_CMD_ASSOCIATE: u8 = 38;
const NL80211_CMD_DEAUTHENTICATE: u8 = 39;
const NL80211_CMD_DISASSOCIATE: u8 = 40;
const NL80211_CMD_MICHAEL_MIC_FAILURE: u8 = 41;
const NL80211_CMD_REG_BEACON_HINT: u8 = 42;
const NL80211_CMD_JOIN_IBSS: u8 = 43;
const NL80211_CMD_LEAVE_IBSS: u8 = 44;
const NL80211_CMD_TESTMODE: u8 = 45;
const NL80211_CMD_CONNECT: u8 = 46;
const NL80211_CMD_ROAM: u8 = 47;
const NL80211_CMD_DISCONNECT: u8 = 48;
const NL80211_CMD_SET_WIPHY_NETNS: u8 = 49;
const NL80211_CMD_GET_SURVEY: u8 = 50;
const NL80211_CMD_NEW_SURVEY_RESULTS: u8 = 51;
const NL80211_CMD_SET_PMKSA: u8 = 52;
const NL80211_CMD_DEL_PMKSA: u8 = 53;
const NL80211_CMD_FLUSH_PMKSA: u8 = 54;
const NL80211_CMD_REMAIN_ON_CHANNEL: u8 = 55;
const NL80211_CMD_CANCEL_REMAIN_ON_CHANNEL: u8 = 56;
const NL80211_CMD_SET_TX_BITRATE_MASK: u8 = 57;
const NL80211_CMD_REGISTER_FRAME: u8 = 58;
const NL80211_CMD_FRAME: u8 = 59;
const NL80211_CMD_FRAME_TX_STATUS: u8 = 60;
const NL80211_CMD_SET_POWER_SAVE: u8 = 61;
const NL80211_CMD_GET_POWER_SAVE: u8 = 62;
const NL80211_CMD_SET_CQM: u8 = 63;
const NL80211_CMD_NOTIFY_CQM: u8 = 64;
const NL80211_CMD_SET_CHANNEL: u8 = 65;
const NL80211_CMD_SET_WDS_PEER: u8 = 66;
const NL80211_CMD_FRAME_WAIT_CANCEL: u8 = 67;
const NL80211_CMD_JOIN_MESH: u8 = 68;
const NL80211_CMD_LEAVE_MESH: u8 = 69;
const NL80211_CMD_UNPROT_DEAUTHENTICATE: u8 = 70;
const NL80211_CMD_UNPROT_DISASSOCIATE: u8 = 71;
const NL80211_CMD_NEW_PEER_CANDIDATE: u8 = 72;
const NL80211_CMD_GET_WOWLAN: u8 = 73;
const NL80211_CMD_SET_WOWLAN: u8 = 74;
const NL80211_CMD_START_SCHED_SCAN: u8 = 75;
const NL80211_CMD_STOP_SCHED_SCAN: u8 = 76;
const NL80211_CMD_SCHED_SCAN_RESULTS: u8 = 77;
const NL80211_CMD_SCHED_SCAN_STOPPED: u8 = 78;
const NL80211_CMD_SET_REKEY_OFFLOAD: u8 = 79;
const NL80211_CMD_PMKSA_CANDIDATE: u8 = 80;
const NL80211_CMD_TDLS_OPER: u8 = 81;
const NL80211_CMD_TDLS_MGMT: u8 = 82;
const NL80211_CMD_UNEXPECTED_FRAME: u8 = 83;
const NL80211_CMD_PROBE_CLIENT: u8 = 84;
const NL80211_CMD_REGISTER_BEACONS: u8 = 85;
const NL80211_CMD_UNEXPECTED_4ADDR_FRAME: u8 = 86;
const NL80211_CMD_SET_NOACK_MAP: u8 = 87;
const NL80211_CMD_CH_SWITCH_NOTIFY: u8 = 88;
const NL80211_CMD_START_P2P_DEVICE: u8 = 89;
const NL80211_CMD_STOP_P2P_DEVICE: u8 = 90;
const NL80211_CMD_CONN_FAILED: u8 = 91;
const NL80211_CMD_SET_MCAST_RATE: u8 = 92;
const NL80211_CMD_SET_MAC_ACL: u8 = 93;
const NL80211_CMD_RADAR_DETECT: u8 = 94;
const NL80211_CMD_GET_PROTOCOL_FEATURES: u8 = 95;
const NL80211_CMD_UPDATE_FT_IES: u8 = 96;
const NL80211_CMD_FT_EVENT: u8 = 97;
const NL80211_CMD_CRIT_PROTOCOL_START: u8 = 98;
const NL80211_CMD_CRIT_PROTOCOL_STOP: u8 = 99;
const NL80211_CMD_GET_COALESCE: u8 = 100;
const NL80211_CMD_SET_COALESCE: u8 = 101;
const NL80211_CMD_CHANNEL_SWITCH: u8 = 102;
const NL80211_CMD_VENDOR: u8 = 103;
const NL80211_CMD_SET_QOS_MAP: u8 = 104;
const NL80211_CMD_ADD_TX_TS: u8 = 105;
const NL80211_CMD_DEL_TX_TS: u8 = 106;
const NL80211_CMD_GET_MPP: u8 = 107;
const NL80211_CMD_JOIN_OCB: u8 = 108;
const NL80211_CMD_LEAVE_OCB: u8 = 109;
const NL80211_CMD_CH_SWITCH_STARTED_NOTIFY: u8 = 110;
const NL80211_CMD_TDLS_CHANNEL_SWITCH: u8 = 111;
const NL80211_CMD_TDLS_CANCEL_CHANNEL_SWITCH: u8 = 112;
const NL80211_CMD_WIPHY_REG_CHANGE: u8 = 113;
const NL80211_CMD_ABORT_SCAN: u8 = 114;
const NL80211_CMD_START_NAN: u8 = 115;
const NL80211_CMD_STOP_NAN: u8 = 116;
const NL80211_CMD_ADD_NAN_FUNCTION: u8 = 117;
const NL80211_CMD_DEL_NAN_FUNCTION: u8 = 118;
const NL80211_CMD_CHANGE_NAN_CONFIG: u8 = 119;
const NL80211_CMD_NAN_MATCH: u8 = 120;
const NL80211_CMD_SET_MULTICAST_TO_UNICAST: u8 = 121;
const NL80211_CMD_UPDATE_CONNECT_PARAMS: u8 = 122;
const NL80211_CMD_SET_PMK: u8 = 123;
const NL80211_CMD_DEL_PMK: u8 = 124;
const NL80211_CMD_PORT_AUTHORIZED: u8 = 125;
const NL80211_CMD_RELOAD_REGDB: u8 = 126;
const NL80211_CMD_EXTERNAL_AUTH: u8 = 127;
const NL80211_CMD_STA_OPMODE_CHANGED: u8 = 128;
const NL80211_CMD_CONTROL_PORT_FRAME: u8 = 129;
const NL80211_CMD_GET_FTM_RESPONDER_STATS: u8 = 130;
const NL80211_CMD_PEER_MEASUREMENT_START: u8 = 131;
const NL80211_CMD_PEER_MEASUREMENT_RESULT: u8 = 132;
const NL80211_CMD_PEER_MEASUREMENT_COMPLETE: u8 = 133;
const NL80211_CMD_NOTIFY_RADAR: u8 = 134;
const NL80211_CMD_UPDATE_OWE_INFO: u8 = 135;
const NL80211_CMD_PROBE_MESH_LINK: u8 = 136;
const NL80211_CMD_SET_TID_CONFIG: u8 = 137;
const NL80211_CMD_UNPROT_BEACON: u8 = 138;
const NL80211_CMD_CONTROL_PORT_FRAME_TX_STATUS: u8 = 139;
const NL80211_CMD_SET_SAR_SPECS: u8 = 140;
const NL80211_CMD_OBSS_COLOR_COLLISION: u8 = 141;
const NL80211_CMD_COLOR_CHANGE_REQUEST: u8 = 142;
const NL80211_CMD_COLOR_CHANGE_STARTED: u8 = 143;
const NL80211_CMD_COLOR_CHANGE_ABORTED: u8 = 144;
const NL80211_CMD_COLOR_CHANGE_COMPLETED: u8 = 145;
const NL80211_CMD_SET_FILS_AAD: u8 = 146;
const NL80211_CMD_ASSOC_COMEBACK: u8 = 147;
const NL80211_CMD_ADD_LINK: u8 = 148;
const NL80211_CMD_REMOVE_LINK: u8 = 149;
const NL80211_CMD_ADD_LINK_STA: u8 = 150;
const NL80211_CMD_MODIFY_LINK_STA: u8 = 151;
const NL80211_CMD_REMOVE_LINK_STA: u8 = 152;
const NL80211_CMD_SET_HW_TIMESTAMP: u8 = 153;
const NL80211_CMD_LINKS_REMOVED: u8 = 154;
const NL80211_CMD_SET_TID_TO_LINK_MAPPING: u8 = 155;

const NL80211_CMD_NEW_BEACON: u8 = NL80211_CMD_START_AP;
const NL80211_CMD_DEL_BEACON: u8 = NL80211_CMD_STOP_AP;
const NL80211_CMD_REGISTER_ACTION: u8 = NL80211_CMD_REGISTER_FRAME;
const NL80211_CMD_ACTION: u8 = NL80211_CMD_FRAME;
const NL80211_CMD_ACTION_TX_STATUS: u8 = NL80211_CMD_FRAME_TX_STATUS;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Nl80211Command {
    GetWiphy,
    SetWiphy,
    NewWiphy,
    DelWiphy,
    GetInterface,
    SetInterface,
    NewInterface,
    DelInterface,
    GetKey,
    SetKey,
    NewKey,
    DelKey,
    GetBeacon,
    SetBeacon,
    StartAp,
    StopAp,
    GetStation,
    SetStation,
    NewStation,
    DelStation,
    GetMpath,
    SetMpath,
    NewMpath,
    DelMpath,
    SetBss,
    SetReg,
    ReqSetReg,
    GetMeshConfig,
    SetMeshConfig,
    SetMgmtExtraIe,
    GetReg,
    GetScan,
    TriggerScan,
    NewScanResults,
    ScanAborted,
    RegChange,
    Authenticate,
    Associate,
    Deauthenticate,
    Disassociate,
    MichaelMicFailure,
    RegBeaconHint,
    JoinIbss,
    LeaveIbss,
    Testmode,
    Connect,
    Roam,
    Disconnect,
    SetWiphyNetns,
    GetSurvey,
    NewSurveyResults,
    SetPmksa,
    DelPmksa,
    FlushPmksa,
    RemainOnChannel,
    CancelRemainOnChannel,
    SetTxBitrateMask,
    RegisterFrame,
    Frame,
    FrameTxStatus,
    SetPowerSave,
    GetPowerSave,
    SetCqm,
    NotifyCqm,
    SetChannel,
    SetWdsPeer,
    FrameWaitCancel,
    JoinMesh,
    LeaveMesh,
    UnprotDeauthenticate,
    UnprotDisassociate,
    NewPeerCandidate,
    GetWowlan,
    SetWowlan,
    StartSchedScan,
    StopSchedScan,
    SchedScanResults,
    SchedScanStopped,
    SetRekeyOffload,
    PmksaCandidate,
    TdlsOper,
    TdlsMgmt,
    UnexpectedFrame,
    ProbeClient,
    RegisterBeacons,
    Unexpected4addrFrame,
    SetNoackMap,
    ChSwitchNotify,
    StartP2PDevice,
    StopP2PDevice,
    ConnFailed,
    SetMcastRate,
    SetMacAcl,
    RadarDetect,
    GetProtocolFeatures,
    UpdateFtIes,
    FtEvent,
    CritProtocolStart,
    CritProtocolStop,
    GetCoalesce,
    SetCoalesce,
    ChannelSwitch,
    Vendor,
    SetQosMap,
    AddTxTs,
    DelTxTs,
    GetMpp,
    JoinOcb,
    LeaveOcb,
    ChSwitchStartedNotify,
    TdlsChannelSwitch,
    TdlsCancelChannelSwitch,
    WiphyRegChange,
    AbortScan,
    StartNan,
    StopNan,
    AddNanFunction,
    DelNanFunction,
    ChangeNanConfig,
    NanMatch,
    SetMulticastToUnicast,
    UpdateConnectParams,
    SetPmk,
    DelPmk,
    PortAuthorized,
    ReloadRegdb,
    ExternalAuth,
    StaOpmodeChanged,
    ControlPortFrame,
    GetFtmResponderStats,
    PeerMeasurementStart,
    PeerMeasurementResult,
    PeerMeasurementComplete,
    NotifyRadar,
    UpdateOweInfo,
    ProbeMeshLink,
    SetTidConfig,
    UnprotBeacon,
    ControlPortFrameTxStatus,
    SetSarSpecs,
    ObssColorCollision,
    ColorChangeRequest,
    ColorChangeStarted,
    ColorChangeAborted,
    ColorChangeCompleted,
    SetFilsAad,
    AssocComeback,
    AddLink,
    RemoveLink,
    AddLinkSta,
    ModifyLinkSta,
    RemoveLinkSta,
    SetHwTimestamp,
    LinksRemoved,
    SetTidToLinkMapping,
    Other(u8),

    // Below are aliases
    NewBeacon,
    DelBeacon,
    RegisterAction,
    Action,
    ActionTxStatus,
}

impl From<u8> for Nl80211Command {
    fn from(d: u8) -> Self {
        match d {
            NL80211_CMD_GET_WIPHY => Self::GetWiphy,
            NL80211_CMD_SET_WIPHY => Self::SetWiphy,
            NL80211_CMD_NEW_WIPHY => Self::NewWiphy,
            NL80211_CMD_DEL_WIPHY => Self::DelWiphy,
            NL80211_CMD_GET_INTERFACE => Self::GetInterface,
            NL80211_CMD_SET_INTERFACE => Self::SetInterface,
            NL80211_CMD_NEW_INTERFACE => Self::NewInterface,
            NL80211_CMD_DEL_INTERFACE => Self::DelInterface,
            NL80211_CMD_GET_KEY => Self::GetKey,
            NL80211_CMD_SET_KEY => Self::SetKey,
            NL80211_CMD_NEW_KEY => Self::NewKey,
            NL80211_CMD_DEL_KEY => Self::DelKey,
            NL80211_CMD_GET_BEACON => Self::GetBeacon,
            NL80211_CMD_SET_BEACON => Self::SetBeacon,
            NL80211_CMD_START_AP => Self::StartAp,
            NL80211_CMD_STOP_AP => Self::StopAp,
            NL80211_CMD_GET_STATION => Self::GetStation,
            NL80211_CMD_SET_STATION => Self::SetStation,
            NL80211_CMD_NEW_STATION => Self::NewStation,
            NL80211_CMD_DEL_STATION => Self::DelStation,
            NL80211_CMD_GET_MPATH => Self::GetMpath,
            NL80211_CMD_SET_MPATH => Self::SetMpath,
            NL80211_CMD_NEW_MPATH => Self::NewMpath,
            NL80211_CMD_DEL_MPATH => Self::DelMpath,
            NL80211_CMD_SET_BSS => Self::SetBss,
            NL80211_CMD_SET_REG => Self::SetReg,
            NL80211_CMD_REQ_SET_REG => Self::ReqSetReg,
            NL80211_CMD_GET_MESH_CONFIG => Self::GetMeshConfig,
            NL80211_CMD_SET_MESH_CONFIG => Self::SetMeshConfig,
            NL80211_CMD_SET_MGMT_EXTRA_IE => Self::SetMgmtExtraIe,
            NL80211_CMD_GET_REG => Self::GetReg,
            NL80211_CMD_GET_SCAN => Self::GetScan,
            NL80211_CMD_TRIGGER_SCAN => Self::TriggerScan,
            NL80211_CMD_NEW_SCAN_RESULTS => Self::NewScanResults,
            NL80211_CMD_SCAN_ABORTED => Self::ScanAborted,
            NL80211_CMD_REG_CHANGE => Self::RegChange,
            NL80211_CMD_AUTHENTICATE => Self::Authenticate,
            NL80211_CMD_ASSOCIATE => Self::Associate,
            NL80211_CMD_DEAUTHENTICATE => Self::Deauthenticate,
            NL80211_CMD_DISASSOCIATE => Self::Disassociate,
            NL80211_CMD_MICHAEL_MIC_FAILURE => Self::MichaelMicFailure,
            NL80211_CMD_REG_BEACON_HINT => Self::RegBeaconHint,
            NL80211_CMD_JOIN_IBSS => Self::JoinIbss,
            NL80211_CMD_LEAVE_IBSS => Self::LeaveIbss,
            NL80211_CMD_TESTMODE => Self::Testmode,
            NL80211_CMD_CONNECT => Self::Connect,
            NL80211_CMD_ROAM => Self::Roam,
            NL80211_CMD_DISCONNECT => Self::Disconnect,
            NL80211_CMD_SET_WIPHY_NETNS => Self::SetWiphyNetns,
            NL80211_CMD_GET_SURVEY => Self::GetSurvey,
            NL80211_CMD_NEW_SURVEY_RESULTS => Self::NewSurveyResults,
            NL80211_CMD_SET_PMKSA => Self::SetPmksa,
            NL80211_CMD_DEL_PMKSA => Self::DelPmksa,
            NL80211_CMD_FLUSH_PMKSA => Self::FlushPmksa,
            NL80211_CMD_REMAIN_ON_CHANNEL => Self::RemainOnChannel,
            NL80211_CMD_CANCEL_REMAIN_ON_CHANNEL => Self::CancelRemainOnChannel,
            NL80211_CMD_SET_TX_BITRATE_MASK => Self::SetTxBitrateMask,
            NL80211_CMD_REGISTER_FRAME => Self::RegisterFrame,
            NL80211_CMD_FRAME => Self::Frame,
            NL80211_CMD_FRAME_TX_STATUS => Self::FrameTxStatus,
            NL80211_CMD_SET_POWER_SAVE => Self::SetPowerSave,
            NL80211_CMD_GET_POWER_SAVE => Self::GetPowerSave,
            NL80211_CMD_SET_CQM => Self::SetCqm,
            NL80211_CMD_NOTIFY_CQM => Self::NotifyCqm,
            NL80211_CMD_SET_CHANNEL => Self::SetChannel,
            NL80211_CMD_SET_WDS_PEER => Self::SetWdsPeer,
            NL80211_CMD_FRAME_WAIT_CANCEL => Self::FrameWaitCancel,
            NL80211_CMD_JOIN_MESH => Self::JoinMesh,
            NL80211_CMD_LEAVE_MESH => Self::LeaveMesh,
            NL80211_CMD_UNPROT_DEAUTHENTICATE => Self::UnprotDeauthenticate,
            NL80211_CMD_UNPROT_DISASSOCIATE => Self::UnprotDisassociate,
            NL80211_CMD_NEW_PEER_CANDIDATE => Self::NewPeerCandidate,
            NL80211_CMD_GET_WOWLAN => Self::GetWowlan,
            NL80211_CMD_SET_WOWLAN => Self::SetWowlan,
            NL80211_CMD_START_SCHED_SCAN => Self::StartSchedScan,
            NL80211_CMD_STOP_SCHED_SCAN => Self::StopSchedScan,
            NL80211_CMD_SCHED_SCAN_RESULTS => Self::SchedScanResults,
            NL80211_CMD_SCHED_SCAN_STOPPED => Self::SchedScanStopped,
            NL80211_CMD_SET_REKEY_OFFLOAD => Self::SetRekeyOffload,
            NL80211_CMD_PMKSA_CANDIDATE => Self::PmksaCandidate,
            NL80211_CMD_TDLS_OPER => Self::TdlsOper,
            NL80211_CMD_TDLS_MGMT => Self::TdlsMgmt,
            NL80211_CMD_UNEXPECTED_FRAME => Self::UnexpectedFrame,
            NL80211_CMD_PROBE_CLIENT => Self::ProbeClient,
            NL80211_CMD_REGISTER_BEACONS => Self::RegisterBeacons,
            NL80211_CMD_UNEXPECTED_4ADDR_FRAME => Self::Unexpected4addrFrame,
            NL80211_CMD_SET_NOACK_MAP => Self::SetNoackMap,
            NL80211_CMD_CH_SWITCH_NOTIFY => Self::ChSwitchNotify,
            NL80211_CMD_START_P2P_DEVICE => Self::StartP2PDevice,
            NL80211_CMD_STOP_P2P_DEVICE => Self::StopP2PDevice,
            NL80211_CMD_CONN_FAILED => Self::ConnFailed,
            NL80211_CMD_SET_MCAST_RATE => Self::SetMcastRate,
            NL80211_CMD_SET_MAC_ACL => Self::SetMacAcl,
            NL80211_CMD_RADAR_DETECT => Self::RadarDetect,
            NL80211_CMD_GET_PROTOCOL_FEATURES => Self::GetProtocolFeatures,
            NL80211_CMD_UPDATE_FT_IES => Self::UpdateFtIes,
            NL80211_CMD_FT_EVENT => Self::FtEvent,
            NL80211_CMD_CRIT_PROTOCOL_START => Self::CritProtocolStart,
            NL80211_CMD_CRIT_PROTOCOL_STOP => Self::CritProtocolStop,
            NL80211_CMD_GET_COALESCE => Self::GetCoalesce,
            NL80211_CMD_SET_COALESCE => Self::SetCoalesce,
            NL80211_CMD_CHANNEL_SWITCH => Self::ChannelSwitch,
            NL80211_CMD_VENDOR => Self::Vendor,
            NL80211_CMD_SET_QOS_MAP => Self::SetQosMap,
            NL80211_CMD_ADD_TX_TS => Self::AddTxTs,
            NL80211_CMD_DEL_TX_TS => Self::DelTxTs,
            NL80211_CMD_GET_MPP => Self::GetMpp,
            NL80211_CMD_JOIN_OCB => Self::JoinOcb,
            NL80211_CMD_LEAVE_OCB => Self::LeaveOcb,
            NL80211_CMD_CH_SWITCH_STARTED_NOTIFY => Self::ChSwitchStartedNotify,
            NL80211_CMD_TDLS_CHANNEL_SWITCH => Self::TdlsChannelSwitch,
            NL80211_CMD_TDLS_CANCEL_CHANNEL_SWITCH => {
                Self::TdlsCancelChannelSwitch
            }
            NL80211_CMD_WIPHY_REG_CHANGE => Self::WiphyRegChange,
            NL80211_CMD_ABORT_SCAN => Self::AbortScan,
            NL80211_CMD_START_NAN => Self::StartNan,
            NL80211_CMD_STOP_NAN => Self::StopNan,
            NL80211_CMD_ADD_NAN_FUNCTION => Self::AddNanFunction,
            NL80211_CMD_DEL_NAN_FUNCTION => Self::DelNanFunction,
            NL80211_CMD_CHANGE_NAN_CONFIG => Self::ChangeNanConfig,
            NL80211_CMD_NAN_MATCH => Self::NanMatch,
            NL80211_CMD_SET_MULTICAST_TO_UNICAST => Self::SetMulticastToUnicast,
            NL80211_CMD_UPDATE_CONNECT_PARAMS => Self::UpdateConnectParams,
            NL80211_CMD_SET_PMK => Self::SetPmk,
            NL80211_CMD_DEL_PMK => Self::DelPmk,
            NL80211_CMD_PORT_AUTHORIZED => Self::PortAuthorized,
            NL80211_CMD_RELOAD_REGDB => Self::ReloadRegdb,
            NL80211_CMD_EXTERNAL_AUTH => Self::ExternalAuth,
            NL80211_CMD_STA_OPMODE_CHANGED => Self::StaOpmodeChanged,
            NL80211_CMD_CONTROL_PORT_FRAME => Self::ControlPortFrame,
            NL80211_CMD_GET_FTM_RESPONDER_STATS => Self::GetFtmResponderStats,
            NL80211_CMD_PEER_MEASUREMENT_START => Self::PeerMeasurementStart,
            NL80211_CMD_PEER_MEASUREMENT_RESULT => Self::PeerMeasurementResult,
            NL80211_CMD_PEER_MEASUREMENT_COMPLETE => {
                Self::PeerMeasurementComplete
            }
            NL80211_CMD_NOTIFY_RADAR => Self::NotifyRadar,
            NL80211_CMD_UPDATE_OWE_INFO => Self::UpdateOweInfo,
            NL80211_CMD_PROBE_MESH_LINK => Self::ProbeMeshLink,
            NL80211_CMD_SET_TID_CONFIG => Self::SetTidConfig,
            NL80211_CMD_UNPROT_BEACON => Self::UnprotBeacon,
            NL80211_CMD_CONTROL_PORT_FRAME_TX_STATUS => {
                Self::ControlPortFrameTxStatus
            }
            NL80211_CMD_SET_SAR_SPECS => Self::SetSarSpecs,
            NL80211_CMD_OBSS_COLOR_COLLISION => Self::ObssColorCollision,
            NL80211_CMD_COLOR_CHANGE_REQUEST => Self::ColorChangeRequest,
            NL80211_CMD_COLOR_CHANGE_STARTED => Self::ColorChangeStarted,
            NL80211_CMD_COLOR_CHANGE_ABORTED => Self::ColorChangeAborted,
            NL80211_CMD_COLOR_CHANGE_COMPLETED => Self::ColorChangeCompleted,
            NL80211_CMD_SET_FILS_AAD => Self::SetFilsAad,
            NL80211_CMD_ASSOC_COMEBACK => Self::AssocComeback,
            NL80211_CMD_ADD_LINK => Self::AddLink,
            NL80211_CMD_REMOVE_LINK => Self::RemoveLink,
            NL80211_CMD_ADD_LINK_STA => Self::AddLinkSta,
            NL80211_CMD_MODIFY_LINK_STA => Self::ModifyLinkSta,
            NL80211_CMD_REMOVE_LINK_STA => Self::RemoveLinkSta,
            NL80211_CMD_SET_HW_TIMESTAMP => Self::SetHwTimestamp,
            NL80211_CMD_LINKS_REMOVED => Self::LinksRemoved,
            NL80211_CMD_SET_TID_TO_LINK_MAPPING => Self::SetTidToLinkMapping,
            _ => Self::Other(d),
        }
    }
}

impl From<Nl80211Command> for u8 {
    fn from(v: Nl80211Command) -> u8 {
        match v {
            Nl80211Command::GetWiphy => NL80211_CMD_GET_WIPHY,
            Nl80211Command::SetWiphy => NL80211_CMD_SET_WIPHY,
            Nl80211Command::NewWiphy => NL80211_CMD_NEW_WIPHY,
            Nl80211Command::DelWiphy => NL80211_CMD_DEL_WIPHY,
            Nl80211Command::GetInterface => NL80211_CMD_GET_INTERFACE,
            Nl80211Command::SetInterface => NL80211_CMD_SET_INTERFACE,
            Nl80211Command::NewInterface => NL80211_CMD_NEW_INTERFACE,
            Nl80211Command::DelInterface => NL80211_CMD_DEL_INTERFACE,
            Nl80211Command::GetKey => NL80211_CMD_GET_KEY,
            Nl80211Command::SetKey => NL80211_CMD_SET_KEY,
            Nl80211Command::NewKey => NL80211_CMD_NEW_KEY,
            Nl80211Command::DelKey => NL80211_CMD_DEL_KEY,
            Nl80211Command::GetBeacon => NL80211_CMD_GET_BEACON,
            Nl80211Command::SetBeacon => NL80211_CMD_SET_BEACON,
            Nl80211Command::StartAp => NL80211_CMD_START_AP,
            Nl80211Command::StopAp => NL80211_CMD_STOP_AP,
            Nl80211Command::GetStation => NL80211_CMD_GET_STATION,
            Nl80211Command::SetStation => NL80211_CMD_SET_STATION,
            Nl80211Command::NewStation => NL80211_CMD_NEW_STATION,
            Nl80211Command::DelStation => NL80211_CMD_DEL_STATION,
            Nl80211Command::GetMpath => NL80211_CMD_GET_MPATH,
            Nl80211Command::SetMpath => NL80211_CMD_SET_MPATH,
            Nl80211Command::NewMpath => NL80211_CMD_NEW_MPATH,
            Nl80211Command::DelMpath => NL80211_CMD_DEL_MPATH,
            Nl80211Command::SetBss => NL80211_CMD_SET_BSS,
            Nl80211Command::SetReg => NL80211_CMD_SET_REG,
            Nl80211Command::ReqSetReg => NL80211_CMD_REQ_SET_REG,
            Nl80211Command::GetMeshConfig => NL80211_CMD_GET_MESH_CONFIG,
            Nl80211Command::SetMeshConfig => NL80211_CMD_SET_MESH_CONFIG,
            Nl80211Command::SetMgmtExtraIe => NL80211_CMD_SET_MGMT_EXTRA_IE,
            Nl80211Command::GetReg => NL80211_CMD_GET_REG,
            Nl80211Command::GetScan => NL80211_CMD_GET_SCAN,
            Nl80211Command::TriggerScan => NL80211_CMD_TRIGGER_SCAN,
            Nl80211Command::NewScanResults => NL80211_CMD_NEW_SCAN_RESULTS,
            Nl80211Command::ScanAborted => NL80211_CMD_SCAN_ABORTED,
            Nl80211Command::RegChange => NL80211_CMD_REG_CHANGE,
            Nl80211Command::Authenticate => NL80211_CMD_AUTHENTICATE,
            Nl80211Command::Associate => NL80211_CMD_ASSOCIATE,
            Nl80211Command::Deauthenticate => NL80211_CMD_DEAUTHENTICATE,
            Nl80211Command::Disassociate => NL80211_CMD_DISASSOCIATE,
            Nl80211Command::MichaelMicFailure => {
                NL80211_CMD_MICHAEL_MIC_FAILURE
            }
            Nl80211Command::RegBeaconHint => NL80211_CMD_REG_BEACON_HINT,
            Nl80211Command::JoinIbss => NL80211_CMD_JOIN_IBSS,
            Nl80211Command::LeaveIbss => NL80211_CMD_LEAVE_IBSS,
            Nl80211Command::Testmode => NL80211_CMD_TESTMODE,
            Nl80211Command::Connect => NL80211_CMD_CONNECT,
            Nl80211Command::Roam => NL80211_CMD_ROAM,
            Nl80211Command::Disconnect => NL80211_CMD_DISCONNECT,
            Nl80211Command::SetWiphyNetns => NL80211_CMD_SET_WIPHY_NETNS,
            Nl80211Command::GetSurvey => NL80211_CMD_GET_SURVEY,
            Nl80211Command::NewSurveyResults => NL80211_CMD_NEW_SURVEY_RESULTS,
            Nl80211Command::SetPmksa => NL80211_CMD_SET_PMKSA,
            Nl80211Command::DelPmksa => NL80211_CMD_DEL_PMKSA,
            Nl80211Command::FlushPmksa => NL80211_CMD_FLUSH_PMKSA,
            Nl80211Command::RemainOnChannel => NL80211_CMD_REMAIN_ON_CHANNEL,
            Nl80211Command::CancelRemainOnChannel => {
                NL80211_CMD_CANCEL_REMAIN_ON_CHANNEL
            }
            Nl80211Command::SetTxBitrateMask => NL80211_CMD_SET_TX_BITRATE_MASK,
            Nl80211Command::RegisterFrame => NL80211_CMD_REGISTER_FRAME,
            Nl80211Command::Frame => NL80211_CMD_FRAME,
            Nl80211Command::FrameTxStatus => NL80211_CMD_FRAME_TX_STATUS,
            Nl80211Command::SetPowerSave => NL80211_CMD_SET_POWER_SAVE,
            Nl80211Command::GetPowerSave => NL80211_CMD_GET_POWER_SAVE,
            Nl80211Command::SetCqm => NL80211_CMD_SET_CQM,
            Nl80211Command::NotifyCqm => NL80211_CMD_NOTIFY_CQM,
            Nl80211Command::SetChannel => NL80211_CMD_SET_CHANNEL,
            Nl80211Command::SetWdsPeer => NL80211_CMD_SET_WDS_PEER,
            Nl80211Command::FrameWaitCancel => NL80211_CMD_FRAME_WAIT_CANCEL,
            Nl80211Command::JoinMesh => NL80211_CMD_JOIN_MESH,
            Nl80211Command::LeaveMesh => NL80211_CMD_LEAVE_MESH,
            Nl80211Command::UnprotDeauthenticate => {
                NL80211_CMD_UNPROT_DEAUTHENTICATE
            }
            Nl80211Command::UnprotDisassociate => {
                NL80211_CMD_UNPROT_DISASSOCIATE
            }
            Nl80211Command::NewPeerCandidate => NL80211_CMD_NEW_PEER_CANDIDATE,
            Nl80211Command::GetWowlan => NL80211_CMD_GET_WOWLAN,
            Nl80211Command::SetWowlan => NL80211_CMD_SET_WOWLAN,
            Nl80211Command::StartSchedScan => NL80211_CMD_START_SCHED_SCAN,
            Nl80211Command::StopSchedScan => NL80211_CMD_STOP_SCHED_SCAN,
            Nl80211Command::SchedScanResults => NL80211_CMD_SCHED_SCAN_RESULTS,
            Nl80211Command::SchedScanStopped => NL80211_CMD_SCHED_SCAN_STOPPED,
            Nl80211Command::SetRekeyOffload => NL80211_CMD_SET_REKEY_OFFLOAD,
            Nl80211Command::PmksaCandidate => NL80211_CMD_PMKSA_CANDIDATE,
            Nl80211Command::TdlsOper => NL80211_CMD_TDLS_OPER,
            Nl80211Command::TdlsMgmt => NL80211_CMD_TDLS_MGMT,
            Nl80211Command::UnexpectedFrame => NL80211_CMD_UNEXPECTED_FRAME,
            Nl80211Command::ProbeClient => NL80211_CMD_PROBE_CLIENT,
            Nl80211Command::RegisterBeacons => NL80211_CMD_REGISTER_BEACONS,
            Nl80211Command::Unexpected4addrFrame => {
                NL80211_CMD_UNEXPECTED_4ADDR_FRAME
            }
            Nl80211Command::SetNoackMap => NL80211_CMD_SET_NOACK_MAP,
            Nl80211Command::ChSwitchNotify => NL80211_CMD_CH_SWITCH_NOTIFY,
            Nl80211Command::StartP2PDevice => NL80211_CMD_START_P2P_DEVICE,
            Nl80211Command::StopP2PDevice => NL80211_CMD_STOP_P2P_DEVICE,
            Nl80211Command::ConnFailed => NL80211_CMD_CONN_FAILED,
            Nl80211Command::SetMcastRate => NL80211_CMD_SET_MCAST_RATE,
            Nl80211Command::SetMacAcl => NL80211_CMD_SET_MAC_ACL,
            Nl80211Command::RadarDetect => NL80211_CMD_RADAR_DETECT,
            Nl80211Command::GetProtocolFeatures => {
                NL80211_CMD_GET_PROTOCOL_FEATURES
            }
            Nl80211Command::UpdateFtIes => NL80211_CMD_UPDATE_FT_IES,
            Nl80211Command::FtEvent => NL80211_CMD_FT_EVENT,
            Nl80211Command::CritProtocolStart => {
                NL80211_CMD_CRIT_PROTOCOL_START
            }
            Nl80211Command::CritProtocolStop => NL80211_CMD_CRIT_PROTOCOL_STOP,
            Nl80211Command::GetCoalesce => NL80211_CMD_GET_COALESCE,
            Nl80211Command::SetCoalesce => NL80211_CMD_SET_COALESCE,
            Nl80211Command::ChannelSwitch => NL80211_CMD_CHANNEL_SWITCH,
            Nl80211Command::Vendor => NL80211_CMD_VENDOR,
            Nl80211Command::SetQosMap => NL80211_CMD_SET_QOS_MAP,
            Nl80211Command::AddTxTs => NL80211_CMD_ADD_TX_TS,
            Nl80211Command::DelTxTs => NL80211_CMD_DEL_TX_TS,
            Nl80211Command::GetMpp => NL80211_CMD_GET_MPP,
            Nl80211Command::JoinOcb => NL80211_CMD_JOIN_OCB,
            Nl80211Command::LeaveOcb => NL80211_CMD_LEAVE_OCB,
            Nl80211Command::ChSwitchStartedNotify => {
                NL80211_CMD_CH_SWITCH_STARTED_NOTIFY
            }
            Nl80211Command::TdlsChannelSwitch => {
                NL80211_CMD_TDLS_CHANNEL_SWITCH
            }
            Nl80211Command::TdlsCancelChannelSwitch => {
                NL80211_CMD_TDLS_CANCEL_CHANNEL_SWITCH
            }
            Nl80211Command::WiphyRegChange => NL80211_CMD_WIPHY_REG_CHANGE,
            Nl80211Command::AbortScan => NL80211_CMD_ABORT_SCAN,
            Nl80211Command::StartNan => NL80211_CMD_START_NAN,
            Nl80211Command::StopNan => NL80211_CMD_STOP_NAN,
            Nl80211Command::AddNanFunction => NL80211_CMD_ADD_NAN_FUNCTION,
            Nl80211Command::DelNanFunction => NL80211_CMD_DEL_NAN_FUNCTION,
            Nl80211Command::ChangeNanConfig => NL80211_CMD_CHANGE_NAN_CONFIG,
            Nl80211Command::NanMatch => NL80211_CMD_NAN_MATCH,
            Nl80211Command::SetMulticastToUnicast => {
                NL80211_CMD_SET_MULTICAST_TO_UNICAST
            }
            Nl80211Command::UpdateConnectParams => {
                NL80211_CMD_UPDATE_CONNECT_PARAMS
            }
            Nl80211Command::SetPmk => NL80211_CMD_SET_PMK,
            Nl80211Command::DelPmk => NL80211_CMD_DEL_PMK,
            Nl80211Command::PortAuthorized => NL80211_CMD_PORT_AUTHORIZED,
            Nl80211Command::ReloadRegdb => NL80211_CMD_RELOAD_REGDB,
            Nl80211Command::ExternalAuth => NL80211_CMD_EXTERNAL_AUTH,
            Nl80211Command::StaOpmodeChanged => NL80211_CMD_STA_OPMODE_CHANGED,
            Nl80211Command::ControlPortFrame => NL80211_CMD_CONTROL_PORT_FRAME,
            Nl80211Command::GetFtmResponderStats => {
                NL80211_CMD_GET_FTM_RESPONDER_STATS
            }
            Nl80211Command::PeerMeasurementStart => {
                NL80211_CMD_PEER_MEASUREMENT_START
            }
            Nl80211Command::PeerMeasurementResult => {
                NL80211_CMD_PEER_MEASUREMENT_RESULT
            }
            Nl80211Command::PeerMeasurementComplete => {
                NL80211_CMD_PEER_MEASUREMENT_COMPLETE
            }
            Nl80211Command::NotifyRadar => NL80211_CMD_NOTIFY_RADAR,
            Nl80211Command::UpdateOweInfo => NL80211_CMD_UPDATE_OWE_INFO,
            Nl80211Command::ProbeMeshLink => NL80211_CMD_PROBE_MESH_LINK,
            Nl80211Command::SetTidConfig => NL80211_CMD_SET_TID_CONFIG,
            Nl80211Command::UnprotBeacon => NL80211_CMD_UNPROT_BEACON,
            Nl80211Command::ControlPortFrameTxStatus => {
                NL80211_CMD_CONTROL_PORT_FRAME_TX_STATUS
            }
            Nl80211Command::SetSarSpecs => NL80211_CMD_SET_SAR_SPECS,
            Nl80211Command::ObssColorCollision => {
                NL80211_CMD_OBSS_COLOR_COLLISION
            }
            Nl80211Command::ColorChangeRequest => {
                NL80211_CMD_COLOR_CHANGE_REQUEST
            }
            Nl80211Command::ColorChangeStarted => {
                NL80211_CMD_COLOR_CHANGE_STARTED
            }
            Nl80211Command::ColorChangeAborted => {
                NL80211_CMD_COLOR_CHANGE_ABORTED
            }
            Nl80211Command::ColorChangeCompleted => {
                NL80211_CMD_COLOR_CHANGE_COMPLETED
            }
            Nl80211Command::SetFilsAad => NL80211_CMD_SET_FILS_AAD,
            Nl80211Command::AssocComeback => NL80211_CMD_ASSOC_COMEBACK,
            Nl80211Command::AddLink => NL80211_CMD_ADD_LINK,
            Nl80211Command::RemoveLink => NL80211_CMD_REMOVE_LINK,
            Nl80211Command::AddLinkSta => NL80211_CMD_ADD_LINK_STA,
            Nl80211Command::ModifyLinkSta => NL80211_CMD_MODIFY_LINK_STA,
            Nl80211Command::RemoveLinkSta => NL80211_CMD_REMOVE_LINK_STA,
            Nl80211Command::SetHwTimestamp => NL80211_CMD_SET_HW_TIMESTAMP,
            Nl80211Command::LinksRemoved => NL80211_CMD_LINKS_REMOVED,
            Nl80211Command::SetTidToLinkMapping => {
                NL80211_CMD_SET_TID_TO_LINK_MAPPING
            }
            Nl80211Command::Other(d) => d,

            Nl80211Command::NewBeacon => NL80211_CMD_NEW_BEACON,
            Nl80211Command::DelBeacon => NL80211_CMD_DEL_BEACON,
            Nl80211Command::RegisterAction => NL80211_CMD_REGISTER_ACTION,
            Nl80211Command::Action => NL80211_CMD_ACTION,
            Nl80211Command::ActionTxStatus => NL80211_CMD_ACTION_TX_STATUS,
        }
    }
}
