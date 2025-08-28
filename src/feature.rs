// SPDX-License-Identifier: MIT

use netlink_packet_core::{DecodeError, Emitable};

const NL80211_FEATURE_SK_TX_STATUS: u32 = 1 << 0;
const NL80211_FEATURE_HT_IBSS: u32 = 1 << 1;
const NL80211_FEATURE_INACTIVITY_TIMER: u32 = 1 << 2;
const NL80211_FEATURE_CELL_BASE_REG_HINTS: u32 = 1 << 3;
const NL80211_FEATURE_P2P_DEVICE_NEEDS_CHANNEL: u32 = 1 << 4;
const NL80211_FEATURE_SAE: u32 = 1 << 5;
const NL80211_FEATURE_LOW_PRIORITY_SCAN: u32 = 1 << 6;
const NL80211_FEATURE_SCAN_FLUSH: u32 = 1 << 7;
const NL80211_FEATURE_AP_SCAN: u32 = 1 << 8;
const NL80211_FEATURE_VIF_TXPOWER: u32 = 1 << 9;
const NL80211_FEATURE_NEED_OBSS_SCAN: u32 = 1 << 10;
const NL80211_FEATURE_P2P_GO_CTWIN: u32 = 1 << 11;
const NL80211_FEATURE_P2P_GO_OPPPS: u32 = 1 << 12;
// bit 13 is reserved
const NL80211_FEATURE_ADVERTISE_CHAN_LIMITS: u32 = 1 << 14;
const NL80211_FEATURE_FULL_AP_CLIENT_STATE: u32 = 1 << 15;
const NL80211_FEATURE_USERSPACE_MPM: u32 = 1 << 16;
const NL80211_FEATURE_ACTIVE_MONITOR: u32 = 1 << 17;
const NL80211_FEATURE_AP_MODE_CHAN_WIDTH_CHANGE: u32 = 1 << 18;
const NL80211_FEATURE_DS_PARAM_SET_IE_IN_PROBES: u32 = 1 << 19;
const NL80211_FEATURE_WFA_TPC_IE_IN_PROBES: u32 = 1 << 20;
const NL80211_FEATURE_QUIET: u32 = 1 << 21;
const NL80211_FEATURE_TX_POWER_INSERTION: u32 = 1 << 22;
const NL80211_FEATURE_ACKTO_ESTIMATION: u32 = 1 << 23;
const NL80211_FEATURE_STATIC_SMPS: u32 = 1 << 24;
const NL80211_FEATURE_DYNAMIC_SMPS: u32 = 1 << 25;
const NL80211_FEATURE_SUPPORTS_WMM_ADMISSION: u32 = 1 << 26;
const NL80211_FEATURE_MAC_ON_CREATE: u32 = 1 << 27;
const NL80211_FEATURE_TDLS_CHANNEL_SWITCH: u32 = 1 << 28;
const NL80211_FEATURE_SCAN_RANDOM_MAC_ADDR: u32 = 1 << 29;
const NL80211_FEATURE_SCHED_SCAN_RANDOM_MAC_ADDR: u32 = 1 << 30;
const NL80211_FEATURE_ND_RANDOM_MAC_ADDR: u32 = 1 << 31;

bitflags::bitflags! {
    #[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
    #[non_exhaustive]
    pub struct Nl80211Features: u32 {
        const SkTxStatus = NL80211_FEATURE_SK_TX_STATUS;
        const HtIbss = NL80211_FEATURE_HT_IBSS;
        const InactivityTimer = NL80211_FEATURE_INACTIVITY_TIMER;
        const CellBaseRegHints = NL80211_FEATURE_CELL_BASE_REG_HINTS;
        const P2pDeviceNeedsChannel = NL80211_FEATURE_P2P_DEVICE_NEEDS_CHANNEL;
        const Sae = NL80211_FEATURE_SAE;
        const LowPriorityScan = NL80211_FEATURE_LOW_PRIORITY_SCAN;
        const ScanFlush = NL80211_FEATURE_SCAN_FLUSH;
        const ApScan = NL80211_FEATURE_AP_SCAN;
        const VifTxpower = NL80211_FEATURE_VIF_TXPOWER;
        const NeedObssScan = NL80211_FEATURE_NEED_OBSS_SCAN;
        const P2pGoCtwin = NL80211_FEATURE_P2P_GO_CTWIN;
        const P2pGoOppps = NL80211_FEATURE_P2P_GO_OPPPS;
        const AdvertiseChanLimits = NL80211_FEATURE_ADVERTISE_CHAN_LIMITS;
        const FullApClientState = NL80211_FEATURE_FULL_AP_CLIENT_STATE;
        const UserspaceMpm = NL80211_FEATURE_USERSPACE_MPM;
        const ActiveMonitor = NL80211_FEATURE_ACTIVE_MONITOR;
        const ApModeChanWidthChange = NL80211_FEATURE_AP_MODE_CHAN_WIDTH_CHANGE;
        const DsParamSetIeInProbes = NL80211_FEATURE_DS_PARAM_SET_IE_IN_PROBES;
        const WfaTpcIeInProbes = NL80211_FEATURE_WFA_TPC_IE_IN_PROBES;
        const Quiet = NL80211_FEATURE_QUIET;
        const TxPowerInsertion = NL80211_FEATURE_TX_POWER_INSERTION;
        const AcktoEstimation = NL80211_FEATURE_ACKTO_ESTIMATION;
        const StaticSmps = NL80211_FEATURE_STATIC_SMPS;
        const DynamicSmps = NL80211_FEATURE_DYNAMIC_SMPS;
        const SupportsWmmAdmission = NL80211_FEATURE_SUPPORTS_WMM_ADMISSION;
        const MacOnCreate = NL80211_FEATURE_MAC_ON_CREATE;
        const TdlsChannelSwitch = NL80211_FEATURE_TDLS_CHANNEL_SWITCH;
        const ScanRandomMacAddr = NL80211_FEATURE_SCAN_RANDOM_MAC_ADDR;
        const SchedScanRandomMacAddr =
            NL80211_FEATURE_SCHED_SCAN_RANDOM_MAC_ADDR;
        const NdRandomMacAddr = NL80211_FEATURE_ND_RANDOM_MAC_ADDR;
        const _ = !0;
    }
}

// Kernel is using [u8; DIV_ROUND_UP(NUM_NL80211_EXT_FEATURES, 8)] to
// store these extended features, allowing it to support any count of
// features more than u128. The maximum data type bitflags can use is u128,
// which might be not enough in the future, hence we do it by ourselves without
// using bitflags.
#[derive(Debug, Default, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub(crate) struct Nl80211ExtFeatures(pub(crate) Vec<Nl80211ExtFeature>);

impl Nl80211ExtFeatures {
    // Kernel(6.10.8) is using 9 bytes to store these 68 bits features and
    // will expand to more bytes
    pub(crate) const LENGTH: usize = 9;

    pub(crate) fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let mut features = Vec::new();
        for (index, byte) in payload.iter().enumerate() {
            for pos in 0..7 {
                if (byte & (1 << pos)) >= 1 {
                    let feature = Nl80211ExtFeature::from(index * 8 + pos);
                    if feature != Nl80211ExtFeature::Unknown {
                        features.push(feature);
                    }
                }
            }
        }
        Ok(Self(features))
    }
}

impl Emitable for Nl80211ExtFeatures {
    fn buffer_len(&self) -> usize {
        Self::LENGTH
    }

    fn emit(&self, buffer: &mut [u8]) {
        for feature in self.0.as_slice() {
            let index = *feature as usize / 8;
            let pos = *feature as usize % 8;
            buffer[index] |= 1 << pos;
        }
    }
}

impl From<&Vec<Nl80211ExtFeature>> for Nl80211ExtFeatures {
    fn from(v: &Vec<Nl80211ExtFeature>) -> Self {
        Self(v.clone())
    }
}

// We cannot have Other() as it would make `repr(usize)` not supporting `as`
// casting so we just discard unknown features with a log
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
#[repr(usize)]
pub enum Nl80211ExtFeature {
    VhtIbss = 0,
    Rrm = 1,
    MuMimoAirSniffer = 2,
    ScanStartTime = 3,
    BssParentTsf = 4,
    SetScanDwell = 5,
    BeaconRateLegacy = 6,
    BeaconRateHt = 7,
    BeaconRateVht = 8,
    FilsSta = 9,
    MgmtTxRandomTa = 10,
    MgmtTxRandomTaConnected = 11,
    SchedScanRelativeRssi = 12,
    CqmRssiList = 13,
    FilsSkOffload = 14,
    FourWayHandshakeStaPsk = 15,
    FourWayHandshakeSta1X = 16,
    FilsMaxChannelTime = 17,
    AcceptBcastProbeResp = 18,
    OceProbeReqHighTxRate = 19,
    OceProbeReqDeferralSuppression = 20,
    MfpOptional = 21,
    LowSpanScan = 22,
    LowPowerScan = 23,
    HighAccuracyScan = 24,
    DfsOffload = 25,
    ControlPortOverNl80211 = 26,
    AckSignalSupport = 27,
    Txqs = 28,
    ScanRandomSn = 29,
    ScanMinPreqContent = 30,
    CanReplacePtk0 = 31,
    EnableFtmResponder = 32,
    AirtimeFairness = 33,
    ApPmksaCaching = 34,
    SchedScanBandSpecificRssiThold = 35,
    ExtKeyId = 36,
    StaTxPwr = 37,
    SaeOffload = 38,
    VlanOffload = 39,
    Aql = 40,
    BeaconProtection = 41,
    ControlPortNoPreauth = 42,
    ProtectedTwt = 43,
    DelIbssSta = 44,
    MulticastRegistrations = 45,
    BeaconProtectionClient = 46,
    ScanFreqKhz = 47,
    ControlPortOverNl80211TxStatus = 48,
    OperatingChannelValidation = 49,
    FourWayHandshakeApPsk = 50,
    SaeOffloadAp = 51,
    FilsDiscovery = 52,
    UnsolBcastProbeResp = 53,
    BeaconRateHe = 54,
    SecureLtf = 55,
    SecureRtt = 56,
    ProtRangeNegoAndMeasure = 57,
    BssColor = 58,
    FilsCryptoOffload = 59,
    RadarBackground = 60,
    PoweredAddrChange = 61,
    Punct = 62,
    SecureNan = 63,
    AuthAndDeauthRandomTa = 64,
    OweOffload = 65,
    OweOffloadAp = 66,
    DfsConcurrent = 67,
    SppAmsduSupport = 68,
    // Please check Nl80211ExtFeatures::LENGTH when you adding more features
    #[default]
    Unknown = 0xffff,
}

impl From<usize> for Nl80211ExtFeature {
    fn from(d: usize) -> Self {
        match d {
            d if d == Self::VhtIbss as usize => Self::VhtIbss,
            d if d == Self::Rrm as usize => Self::Rrm,
            d if d == Self::MuMimoAirSniffer as usize => Self::MuMimoAirSniffer,
            d if d == Self::ScanStartTime as usize => Self::ScanStartTime,
            d if d == Self::BssParentTsf as usize => Self::BssParentTsf,
            d if d == Self::SetScanDwell as usize => Self::SetScanDwell,
            d if d == Self::BeaconRateLegacy as usize => Self::BeaconRateLegacy,
            d if d == Self::BeaconRateHt as usize => Self::BeaconRateHt,
            d if d == Self::BeaconRateVht as usize => Self::BeaconRateVht,
            d if d == Self::FilsSta as usize => Self::FilsSta,
            d if d == Self::MgmtTxRandomTa as usize => Self::MgmtTxRandomTa,
            d if d == Self::MgmtTxRandomTaConnected as usize => {
                Self::MgmtTxRandomTaConnected
            }
            d if d == Self::SchedScanRelativeRssi as usize => {
                Self::SchedScanRelativeRssi
            }
            d if d == Self::CqmRssiList as usize => Self::CqmRssiList,
            d if d == Self::FilsSkOffload as usize => Self::FilsSkOffload,
            d if d == Self::FourWayHandshakeStaPsk as usize => {
                Self::FourWayHandshakeStaPsk
            }
            d if d == Self::FourWayHandshakeSta1X as usize => {
                Self::FourWayHandshakeSta1X
            }
            d if d == Self::FilsMaxChannelTime as usize => {
                Self::FilsMaxChannelTime
            }
            d if d == Self::AcceptBcastProbeResp as usize => {
                Self::AcceptBcastProbeResp
            }
            d if d == Self::OceProbeReqHighTxRate as usize => {
                Self::OceProbeReqHighTxRate
            }
            d if d == Self::OceProbeReqDeferralSuppression as usize => {
                Self::OceProbeReqDeferralSuppression
            }
            d if d == Self::MfpOptional as usize => Self::MfpOptional,
            d if d == Self::LowSpanScan as usize => Self::LowSpanScan,
            d if d == Self::LowPowerScan as usize => Self::LowPowerScan,
            d if d == Self::HighAccuracyScan as usize => Self::HighAccuracyScan,
            d if d == Self::DfsOffload as usize => Self::DfsOffload,
            d if d == Self::ControlPortOverNl80211 as usize => {
                Self::ControlPortOverNl80211
            }
            d if d == Self::AckSignalSupport as usize => Self::AckSignalSupport,
            d if d == Self::Txqs as usize => Self::Txqs,
            d if d == Self::ScanRandomSn as usize => Self::ScanRandomSn,
            d if d == Self::ScanMinPreqContent as usize => {
                Self::ScanMinPreqContent
            }
            d if d == Self::CanReplacePtk0 as usize => Self::CanReplacePtk0,
            d if d == Self::EnableFtmResponder as usize => {
                Self::EnableFtmResponder
            }
            d if d == Self::AirtimeFairness as usize => Self::AirtimeFairness,
            d if d == Self::ApPmksaCaching as usize => Self::ApPmksaCaching,
            d if d == Self::SchedScanBandSpecificRssiThold as usize => {
                Self::SchedScanBandSpecificRssiThold
            }
            d if d == Self::ExtKeyId as usize => Self::ExtKeyId,
            d if d == Self::StaTxPwr as usize => Self::StaTxPwr,
            d if d == Self::SaeOffload as usize => Self::SaeOffload,
            d if d == Self::VlanOffload as usize => Self::VlanOffload,
            d if d == Self::Aql as usize => Self::Aql,
            d if d == Self::BeaconProtection as usize => Self::BeaconProtection,
            d if d == Self::ControlPortNoPreauth as usize => {
                Self::ControlPortNoPreauth
            }
            d if d == Self::ProtectedTwt as usize => Self::ProtectedTwt,
            d if d == Self::DelIbssSta as usize => Self::DelIbssSta,
            d if d == Self::MulticastRegistrations as usize => {
                Self::MulticastRegistrations
            }
            d if d == Self::BeaconProtectionClient as usize => {
                Self::BeaconProtectionClient
            }
            d if d == Self::ScanFreqKhz as usize => Self::ScanFreqKhz,
            d if d == Self::ControlPortOverNl80211TxStatus as usize => {
                Self::ControlPortOverNl80211TxStatus
            }
            d if d == Self::OperatingChannelValidation as usize => {
                Self::OperatingChannelValidation
            }
            d if d == Self::FourWayHandshakeApPsk as usize => {
                Self::FourWayHandshakeApPsk
            }
            d if d == Self::SaeOffloadAp as usize => Self::SaeOffloadAp,
            d if d == Self::FilsDiscovery as usize => Self::FilsDiscovery,
            d if d == Self::UnsolBcastProbeResp as usize => {
                Self::UnsolBcastProbeResp
            }
            d if d == Self::BeaconRateHe as usize => Self::BeaconRateHe,
            d if d == Self::SecureLtf as usize => Self::SecureLtf,
            d if d == Self::SecureRtt as usize => Self::SecureRtt,
            d if d == Self::ProtRangeNegoAndMeasure as usize => {
                Self::ProtRangeNegoAndMeasure
            }
            d if d == Self::BssColor as usize => Self::BssColor,
            d if d == Self::FilsCryptoOffload as usize => {
                Self::FilsCryptoOffload
            }
            d if d == Self::RadarBackground as usize => Self::RadarBackground,
            d if d == Self::PoweredAddrChange as usize => {
                Self::PoweredAddrChange
            }
            d if d == Self::Punct as usize => Self::Punct,
            d if d == Self::SecureNan as usize => Self::SecureNan,
            d if d == Self::AuthAndDeauthRandomTa as usize => {
                Self::AuthAndDeauthRandomTa
            }
            d if d == Self::OweOffload as usize => Self::OweOffload,
            d if d == Self::OweOffloadAp as usize => Self::OweOffloadAp,
            d if d == Self::DfsConcurrent as usize => Self::DfsConcurrent,
            d if d == Self::SppAmsduSupport as usize => Self::SppAmsduSupport,
            _ => {
                log::info!("Unsupported feature {d}");
                Self::Unknown
            }
        }
    }
}
