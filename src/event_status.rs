// SPDX-License-Identifier: MIT

use netlink_packet_core::DecodeError;

/// The result status of an authentication / association / connection
/// attempt, from the IEEE 802.11 status code carried in the event.
///
/// Variants cover the IEEE 802.11-2020/2024 status code table; the variant
/// name follows the Linux kernel constant (`WLAN_STATUS_*`, see
/// `include/linux/ieee80211.h`) when one exists, otherwise the name used
/// by the IEEE standard.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum Nl80211EventCode {
    /// IEEE 802.11 status code 0.
    Success,
    /// IEEE 802.11 status code 1.
    UnspecifiedFailure,
    /// IEEE 802.11 status code 2.
    TdlsRejectedAlternativeProvided,
    /// IEEE 802.11 status code 3.
    TdlsRejected,
    /// IEEE 802.11 status code 5.
    SecurityDisabled,
    /// IEEE 802.11 status code 6.
    UnacceptableLifetime,
    /// IEEE 802.11 status code 7.
    NotInSameBss,
    /// IEEE 802.11 status code 10.
    CapsUnsupported,
    /// IEEE 802.11 status code 11.
    ReassocNoAssoc,
    /// IEEE 802.11 status code 12.
    AssocDeniedUnspec,
    /// IEEE 802.11 status code 13.
    NotSupportedAuthAlg,
    /// IEEE 802.11 status code 14.
    UnknownAuthTransaction,
    /// IEEE 802.11 status code 15.
    ChallengeFail,
    /// IEEE 802.11 status code 16.
    AuthTimeout,
    /// IEEE 802.11 status code 17.
    ApUnableToHandleNewSta,
    /// IEEE 802.11 status code 18.
    AssocDeniedRates,
    /// IEEE 802.11 status code 19.
    AssocDeniedNoShortPreamble,
    /// IEEE 802.11 status code 20.
    AssocDeniedNoPbcc,
    /// IEEE 802.11 status code 21.
    AssocDeniedNoAgility,
    /// IEEE 802.11 status code 22.
    AssocDeniedNoSpectrum,
    /// IEEE 802.11 status code 23.
    AssocRejectedBadPower,
    /// IEEE 802.11 status code 24.
    AssocRejectedBadSuppChan,
    /// IEEE 802.11 status code 25.
    AssocDeniedNoShortTime,
    /// IEEE 802.11 status code 26.
    AssocDeniedNoDsssOfdm,
    /// IEEE 802.11 status code 27.
    DeniedNoHtSupport,
    /// IEEE 802.11 status code 28.
    R0khUnreachable,
    /// IEEE 802.11 status code 30.
    AssocRejectedTemporarily,
    /// IEEE 802.11 status code 31.
    RobustMgmtFramePolicyViolation,
    /// IEEE 802.11 status code 32.
    UnspecifiedQos,
    /// IEEE 802.11 status code 33.
    AssocDeniedNoBandwidth,
    /// IEEE 802.11 status code 34.
    AssocDeniedLowAck,
    /// IEEE 802.11 status code 35.
    AssocDeniedUnsuppQos,
    /// IEEE 802.11 status code 37.
    RequestDeclined,
    /// IEEE 802.11 status code 38.
    InvalidQosParam,
    /// IEEE 802.11 status code 39.
    RejectedWithSuggestedChanges,
    /// IEEE 802.11 status code 40.
    InvalidIe,
    /// IEEE 802.11 status code 41.
    InvalidGroupCipher,
    /// IEEE 802.11 status code 42.
    InvalidPairwiseCipher,
    /// IEEE 802.11 status code 43.
    InvalidAkm,
    /// IEEE 802.11 status code 44.
    UnsuppRsnVersion,
    /// IEEE 802.11 status code 45.
    InvalidRsnIeCap,
    /// IEEE 802.11 status code 46.
    CipherSuiteRejected,
    /// IEEE 802.11 status code 47.
    RejectedForDelayPeriod,
    /// IEEE 802.11 status code 48.
    NoDirectLink,
    /// IEEE 802.11 status code 49.
    StaNotPresent,
    /// IEEE 802.11 status code 50.
    StaNotQsta,
    /// IEEE 802.11 status code 51.
    AssocDeniedListenIntervalTooLarge,
    /// IEEE 802.11 status code 52.
    InvalidFtActionFrameCount,
    /// IEEE 802.11 status code 53.
    InvalidPmkid,
    /// IEEE 802.11 status code 54.
    InvalidMde,
    /// IEEE 802.11 status code 55.
    InvalidFte,
    /// IEEE 802.11 status code 56.
    RequestedTclasNotSupported,
    /// IEEE 802.11 status code 57.
    InsufficientTclasProcessingResources,
    /// IEEE 802.11 status code 58.
    TryAnotherBss,
    /// IEEE 802.11 status code 59.
    GasAdvertisementProtocolNotSupported,
    /// IEEE 802.11 status code 60.
    NoOutstandingGasRequest,
    /// IEEE 802.11 status code 61.
    GasResponseNotReceived,
    /// IEEE 802.11 status code 62.
    GasQueryTimeout,
    /// IEEE 802.11 status code 63.
    GasQueryResponseTooLarge,
    /// IEEE 802.11 status code 64.
    RejectedHomeWithSuggestedChanges,
    /// IEEE 802.11 status code 65.
    ServerUnreachable,
    /// IEEE 802.11 status code 67.
    RejectedForSspPermissions,
    /// IEEE 802.11 status code 68.
    RefusedUnauthenticatedAccessNotSupported,
    /// IEEE 802.11 status code 72.
    InvalidRsne,
    /// IEEE 802.11 status code 73.
    UapsdCoexistenceNotSupported,
    /// IEEE 802.11 status code 74.
    UapsdCoexModeNotSupported,
    /// IEEE 802.11 status code 75.
    BadIntervalWithUapsdCoex,
    /// IEEE 802.11 status code 76.
    AntiClogRequired,
    /// IEEE 802.11 status code 77.
    UnsupportedFiniteCyclicGroup,
    /// IEEE 802.11 status code 78.
    CannotFindAlternativeTbtt,
    /// IEEE 802.11 status code 79.
    TransmissionFailure,
    /// IEEE 802.11 status code 81.
    TclasResourcesExhausted,
    /// IEEE 802.11 status code 82.
    RejectedWithSuggestedBssTransition,
    /// IEEE 802.11 status code 83.
    RejectWithSchedule,
    /// IEEE 802.11 status code 84.
    RejectNoWakeupSpecified,
    /// IEEE 802.11 status code 85.
    SuccessPowerSaveMode,
    /// IEEE 802.11 status code 86.
    PendingAdmittingFstSession,
    /// IEEE 802.11 status code 87.
    PerformingFstNow,
    /// IEEE 802.11 status code 88.
    PendingGapInBaWindow,
    /// IEEE 802.11 status code 89.
    RejectUPidSetting,
    /// IEEE 802.11 status code 92.
    RefusedExternalReason,
    /// IEEE 802.11 status code 93.
    RefusedApOutOfMemory,
    /// IEEE 802.11 status code 94.
    RejectedEmergencyServicesNotSupported,
    /// IEEE 802.11 status code 95.
    QueryResponseOutstanding,
    /// IEEE 802.11 status code 96.
    RejectDseBand,
    /// IEEE 802.11 status code 97.
    TclasProcessingTerminated,
    /// IEEE 802.11 status code 98.
    TsScheduleConflict,
    /// IEEE 802.11 status code 99.
    DeniedWithSuggestedBandAndChannel,
    /// IEEE 802.11 status code 100.
    McaopReservationConflict,
    /// IEEE 802.11 status code 101.
    MafLimitExceeded,
    /// IEEE 802.11 status code 102.
    McaTrackLimitExceeded,
    /// IEEE 802.11 status code 103.
    DeniedDueToSpectrumManagement,
    /// IEEE 802.11 status code 104.
    DeniedVhtNotSupported,
    /// IEEE 802.11 status code 105.
    EnablementDenied,
    /// IEEE 802.11 status code 106.
    RestrictionFromAuthorizedGdb,
    /// IEEE 802.11 status code 107.
    AuthorizationDeenabled,
    /// IEEE 802.11 status code 108.
    EnergyLimitedOperationNotSupported,
    /// IEEE 802.11 status code 109.
    RejectedNdpBlockAckSuggested,
    /// IEEE 802.11 status code 110.
    RejectedMaxAwayDurationUnacceptable,
    /// IEEE 802.11 status code 112.
    FilsAuthenticationFailure,
    /// IEEE 802.11 status code 113.
    UnknownAuthenticationServer,
    /// IEEE 802.11 status code 116.
    DeniedNotificationPeriodAllocation,
    /// IEEE 802.11 status code 117.
    DeniedChannelSplitting,
    /// IEEE 802.11 status code 118.
    DeniedAllocation,
    /// IEEE 802.11 status code 119.
    CmmgFeaturesNotSupported,
    /// IEEE 802.11 status code 120.
    GasFragmentNotAvailable,
    /// IEEE 802.11 status code 121.
    SuccessCagVersionsMatch,
    /// IEEE 802.11 status code 122.
    GlkNotAuthorized,
    /// IEEE 802.11 status code 123.
    UnknownPasswordIdentifier,
    /// IEEE 802.11 status code 124.
    DeniedHeNotSupported,
    /// IEEE 802.11 status code 125.
    DeniedLocalMacAddressNotSupported,
    /// IEEE 802.11 status code 126.
    SaeHashToElement,
    /// IEEE 802.11 status code 127.
    SaePk,
    /// IEEE 802.11 status code 133.
    DeniedTidToLinkMapping,
    /// IEEE 802.11 status code 134.
    PrefTidToLinkMappingSuggested,
    /// IEEE 802.11 status code 136.
    InvalidPublicKey,
    /// IEEE 802.11 status code 137.
    PasnBaseAkmFailed,
    /// IEEE 802.11 status code 138.
    OciMismatch,
    /// IEEE 802.11 status code 143.
    GasQueryRequestTooLarge,
    /// IEEE 802.11 status code 153.
    Ieee8021xAuthSuccess,
    /// Any status code not listed above; the raw code is kept.
    Other(u16),
}

/// IEEE 802.11 status codes, named after the IEEE 802.11-2020/2024 standard.
/// (`IEEE_*`)
const IEEE_SUCCESS: u16 = 0;
const IEEE_REFUSED_REASON_UNSPECIFIED: u16 = 1;
const IEEE_TDLS_REJECTED_ALTERNATIVE_PROVIDED: u16 = 2;
const IEEE_TDLS_REJECTED: u16 = 3;
const IEEE_SECURITY_DISABLED: u16 = 5;
const IEEE_UNACCEPTABLE_LIFETIME: u16 = 6;
const IEEE_NOT_IN_SAME_BSS: u16 = 7;
const IEEE_REFUSED_CAPABILITIES_MISMATCH: u16 = 10;
const IEEE_DENIED_NO_ASSOCIATION_EXISTS: u16 = 11;
const IEEE_DENIED_OTHER_REASON: u16 = 12;
const IEEE_UNSUPPORTED_AUTH_ALGORITHM: u16 = 13;
const IEEE_TRANSACTION_SEQUENCE_ERROR: u16 = 14;
const IEEE_CHALLENGE_FAILURE: u16 = 15;
const IEEE_REJECTED_SEQUENCE_TIMEOUT: u16 = 16;
const IEEE_DENIED_NO_MORE_STAS: u16 = 17;
const IEEE_REFUSED_BASIC_RATES_NOT_SUPPORTED: u16 = 18;
const IEEE_DENIED_NO_SHORT_PREAMBLE_SUPPORTED: u16 = 19;
const IEEE_DENIED_NO_PBCC: u16 = 20;
const IEEE_DENIED_NO_AGILITY: u16 = 21;
const IEEE_REJECTED_SPECTRUM_MANAGEMENT_REQUIRED: u16 = 22;
const IEEE_REJECTED_BAD_POWER_CAPABILITY: u16 = 23;
const IEEE_REJECTED_BAD_SUPPORTED_CHANNELS: u16 = 24;
const IEEE_DENIED_NO_SHORT_SLOT_TIME_SUPPORTED: u16 = 25;
const IEEE_DENIED_NO_DSSS_OFDM: u16 = 26;
const IEEE_DENIED_NO_HT_SUPPORT: u16 = 27;
const IEEE_R0KH_UNREACHABLE: u16 = 28;
const IEEE_REFUSED_TEMPORARILY: u16 = 30;
const IEEE_ROBUST_MANAGEMENT_POLICY_VIOLATION: u16 = 31;
const IEEE_UNSPECIFIED_QOS_FAILURE: u16 = 32;
const IEEE_DENIED_INSUFFICIENT_BANDWIDTH: u16 = 33;
const IEEE_DENIED_POOR_CHANNEL_CONDITIONS: u16 = 34;
const IEEE_DENIED_QOS_NOT_SUPPORTED: u16 = 35;
const IEEE_REQUEST_DECLINED: u16 = 37;
const IEEE_INVALID_PARAMETERS: u16 = 38;
const IEEE_REJECTED_WITH_SUGGESTED_CHANGES: u16 = 39;
const IEEE_STATUS_INVALID_ELEMENT: u16 = 40;
const IEEE_STATUS_INVALID_GROUP_CIPHER: u16 = 41;
const IEEE_STATUS_INVALID_PAIRWISE_CIPHER: u16 = 42;
const IEEE_STATUS_INVALID_AKMP: u16 = 43;
const IEEE_UNSUPPORTED_RSNE_VERSION: u16 = 44;
const IEEE_INVALID_RSNE_CAPABILITIES: u16 = 45;
const IEEE_STATUS_CIPHER_OUT_OF_POLICY: u16 = 46;
const IEEE_REJECTED_FOR_DELAY_PERIOD: u16 = 47;
const IEEE_NO_DIRECT_LINK: u16 = 48;
const IEEE_NOT_PRESENT: u16 = 49;
const IEEE_NOT_QOS_STA: u16 = 50;
const IEEE_DENIED_LISTEN_INTERVAL_TOO_LARGE: u16 = 51;
const IEEE_STATUS_INVALID_FT_ACTION_FRAME_COUNT: u16 = 52;
const IEEE_STATUS_INVALID_PMKID: u16 = 53;
const IEEE_STATUS_INVALID_MDE: u16 = 54;
const IEEE_STATUS_INVALID_FTE: u16 = 55;
const IEEE_REQUESTED_TCLAS_NOT_SUPPORTED: u16 = 56;
const IEEE_INSUFFICIENT_TCLAS_PROCESSING_RESOURCES: u16 = 57;
const IEEE_TRY_ANOTHER_BSS: u16 = 58;
const IEEE_GAS_ADVERTISEMENT_PROTOCOL_NOT_SUPPORTED: u16 = 59;
const IEEE_NO_OUTSTANDING_GAS_REQUEST: u16 = 60;
const IEEE_GAS_RESPONSE_NOT_RECEIVED_FROM_SERVER: u16 = 61;
const IEEE_GAS_QUERY_TIMEOUT: u16 = 62;
const IEEE_GAS_QUERY_RESPONSE_TOO_LARGE: u16 = 63;
const IEEE_REJECTED_HOME_WITH_SUGGESTED_CHANGES: u16 = 64;
const IEEE_SERVER_UNREACHABLE: u16 = 65;
const IEEE_REJECTED_FOR_SSP_PERMISSIONS: u16 = 67;
const IEEE_REFUSED_UNAUTHENTICATED_ACCESS_NOT_SUPPORTED: u16 = 68;
const IEEE_INVALID_RSNE: u16 = 72;
const IEEE_U_APSD_COEXISTENCE_NOT_SUPPORTED: u16 = 73;
const IEEE_U_APSD_COEX_MODE_NOT_SUPPORTED: u16 = 74;
const IEEE_BAD_INTERVAL_WITH_U_APSD_COEX: u16 = 75;
const IEEE_ANTI_CLOGGING_TOKEN_REQUIRED: u16 = 76;
const IEEE_UNSUPPORTED_FINITE_CYCLIC_GROUP: u16 = 77;
const IEEE_CANNOT_FIND_ALTERNATIVE_TBTT: u16 = 78;
const IEEE_TRANSMISSION_FAILURE: u16 = 79;
const IEEE_TCLAS_RESOURCES_EXHAUSTED: u16 = 81;
const IEEE_REJECTED_WITH_SUGGESTED_BSS_TRANSITION: u16 = 82;
const IEEE_REJECT_WITH_SCHEDULE: u16 = 83;
const IEEE_REJECT_NO_WAKEUP_SPECIFIED: u16 = 84;
const IEEE_SUCCESS_POWER_SAVE_MODE: u16 = 85;
const IEEE_PENDING_ADMITTING_FST_SESSION: u16 = 86;
const IEEE_PERFORMING_FST_NOW: u16 = 87;
const IEEE_PENDING_GAP_IN_BA_WINDOW: u16 = 88;
const IEEE_REJECT_U_PID_SETTING: u16 = 89;
const IEEE_REFUSED_EXTERNAL_REASON: u16 = 92;
const IEEE_REFUSED_AP_OUT_OF_MEMORY: u16 = 93;
const IEEE_REJECTED_EMERGENCY_SERVICES_NOT_SUPPORTED: u16 = 94;
const IEEE_QUERY_RESPONSE_OUTSTANDING: u16 = 95;
const IEEE_REJECT_DSE_BAND: u16 = 96;
const IEEE_TCLAS_PROCESSING_TERMINATED: u16 = 97;
const IEEE_TS_SCHEDULE_CONFLICT: u16 = 98;
const IEEE_DENIED_WITH_SUGGESTED_BAND_AND_CHANNEL: u16 = 99;
const IEEE_MCCAOP_RESERVATION_CONFLICT: u16 = 100;
const IEEE_MAF_LIMIT_EXCEEDED: u16 = 101;
const IEEE_MCCA_TRACK_LIMIT_EXCEEDED: u16 = 102;
const IEEE_DENIED_DUE_TO_SPECTRUM_MANAGEMENT: u16 = 103;
const IEEE_DENIED_VHT_NOT_SUPPORTED: u16 = 104;
const IEEE_ENABLEMENT_DENIED: u16 = 105;
const IEEE_RESTRICTION_FROM_AUTHORIZED_GDB: u16 = 106;
const IEEE_AUTHORIZATION_DEENABLED: u16 = 107;
const IEEE_ENERGY_LIMITED_OPERATION_NOT_SUPPORTED: u16 = 108;
const IEEE_REJECTED_NDP_BLOCK_ACK_SUGGESTED: u16 = 109;
const IEEE_REJECTED_MAX_AWAY_DURATION_UNACCEPTABLE: u16 = 110;
const IEEE_FILS_AUTHENTICATION_FAILURE: u16 = 112;
const IEEE_UNKNOWN_AUTHENTICATION_SERVER: u16 = 113;
const IEEE_DENIED_NOTIFICATION_PERIOD_ALLOCATION: u16 = 116;
const IEEE_DENIED_CHANNEL_SPLITTING: u16 = 117;
const IEEE_DENIED_ALLOCATION: u16 = 118;
const IEEE_CMMG_FEATURES_NOT_SUPPORTED: u16 = 119;
const IEEE_GAS_FRAGMENT_NOT_AVAILABLE: u16 = 120;
const IEEE_SUCCESS_CAG_VERSIONS_MATCH: u16 = 121;
const IEEE_GLK_NOT_AUTHORIZED: u16 = 122;
const IEEE_UNKNOWN_PASSWORD_IDENTIFIER: u16 = 123;
const IEEE_DENIED_HE_NOT_SUPPORTED: u16 = 124;
const IEEE_DENIED_LOCAL_MAC_ADDRESS_POLICY_VIOLATION: u16 = 125;
const IEEE_SAE_HASH_TO_ELEMENT: u16 = 126;
const IEEE_SAE_PK: u16 = 127;
const IEEE_DENIED_TID_TO_LINK_MAPPING: u16 = 133;
const IEEE_PREFERRED_TID_TO_LINK_MAPPING_SUGGESTED: u16 = 134;
const IEEE_INVALID_PUBLIC_KEY: u16 = 136;
const IEEE_PASN_BASE_AKMP_FAILED: u16 = 137;
const IEEE_OCI_MISMATCH: u16 = 138;
const IEEE_GAS_QUERY_REQUEST_TOO_LARGE: u16 = 143;
const IEEE_8021X_AUTH_SUCCESS: u16 = 153;

impl From<u16> for Nl80211EventCode {
    fn from(v: u16) -> Self {
        match v {
            IEEE_SUCCESS => Self::Success,
            IEEE_REFUSED_REASON_UNSPECIFIED => Self::UnspecifiedFailure,
            IEEE_TDLS_REJECTED_ALTERNATIVE_PROVIDED => {
                Self::TdlsRejectedAlternativeProvided
            }
            IEEE_TDLS_REJECTED => Self::TdlsRejected,
            IEEE_SECURITY_DISABLED => Self::SecurityDisabled,
            IEEE_UNACCEPTABLE_LIFETIME => Self::UnacceptableLifetime,
            IEEE_NOT_IN_SAME_BSS => Self::NotInSameBss,
            IEEE_REFUSED_CAPABILITIES_MISMATCH => Self::CapsUnsupported,
            IEEE_DENIED_NO_ASSOCIATION_EXISTS => Self::ReassocNoAssoc,
            IEEE_DENIED_OTHER_REASON => Self::AssocDeniedUnspec,
            IEEE_UNSUPPORTED_AUTH_ALGORITHM => Self::NotSupportedAuthAlg,
            IEEE_TRANSACTION_SEQUENCE_ERROR => Self::UnknownAuthTransaction,
            IEEE_CHALLENGE_FAILURE => Self::ChallengeFail,
            IEEE_REJECTED_SEQUENCE_TIMEOUT => Self::AuthTimeout,
            IEEE_DENIED_NO_MORE_STAS => Self::ApUnableToHandleNewSta,
            IEEE_REFUSED_BASIC_RATES_NOT_SUPPORTED => Self::AssocDeniedRates,
            IEEE_DENIED_NO_SHORT_PREAMBLE_SUPPORTED => {
                Self::AssocDeniedNoShortPreamble
            }
            IEEE_DENIED_NO_PBCC => Self::AssocDeniedNoPbcc,
            IEEE_DENIED_NO_AGILITY => Self::AssocDeniedNoAgility,
            IEEE_REJECTED_SPECTRUM_MANAGEMENT_REQUIRED => {
                Self::AssocDeniedNoSpectrum
            }
            IEEE_REJECTED_BAD_POWER_CAPABILITY => Self::AssocRejectedBadPower,
            IEEE_REJECTED_BAD_SUPPORTED_CHANNELS => {
                Self::AssocRejectedBadSuppChan
            }
            IEEE_DENIED_NO_SHORT_SLOT_TIME_SUPPORTED => {
                Self::AssocDeniedNoShortTime
            }
            IEEE_DENIED_NO_DSSS_OFDM => Self::AssocDeniedNoDsssOfdm,
            IEEE_DENIED_NO_HT_SUPPORT => Self::DeniedNoHtSupport,
            IEEE_R0KH_UNREACHABLE => Self::R0khUnreachable,
            IEEE_REFUSED_TEMPORARILY => Self::AssocRejectedTemporarily,
            IEEE_ROBUST_MANAGEMENT_POLICY_VIOLATION => {
                Self::RobustMgmtFramePolicyViolation
            }
            IEEE_UNSPECIFIED_QOS_FAILURE => Self::UnspecifiedQos,
            IEEE_DENIED_INSUFFICIENT_BANDWIDTH => Self::AssocDeniedNoBandwidth,
            IEEE_DENIED_POOR_CHANNEL_CONDITIONS => Self::AssocDeniedLowAck,
            IEEE_DENIED_QOS_NOT_SUPPORTED => Self::AssocDeniedUnsuppQos,
            IEEE_REQUEST_DECLINED => Self::RequestDeclined,
            IEEE_INVALID_PARAMETERS => Self::InvalidQosParam,
            IEEE_REJECTED_WITH_SUGGESTED_CHANGES => {
                Self::RejectedWithSuggestedChanges
            }
            IEEE_STATUS_INVALID_ELEMENT => Self::InvalidIe,
            IEEE_STATUS_INVALID_GROUP_CIPHER => Self::InvalidGroupCipher,
            IEEE_STATUS_INVALID_PAIRWISE_CIPHER => Self::InvalidPairwiseCipher,
            IEEE_STATUS_INVALID_AKMP => Self::InvalidAkm,
            IEEE_UNSUPPORTED_RSNE_VERSION => Self::UnsuppRsnVersion,
            IEEE_INVALID_RSNE_CAPABILITIES => Self::InvalidRsnIeCap,
            IEEE_STATUS_CIPHER_OUT_OF_POLICY => Self::CipherSuiteRejected,
            IEEE_REJECTED_FOR_DELAY_PERIOD => Self::RejectedForDelayPeriod,
            IEEE_NO_DIRECT_LINK => Self::NoDirectLink,
            IEEE_NOT_PRESENT => Self::StaNotPresent,
            IEEE_NOT_QOS_STA => Self::StaNotQsta,
            IEEE_DENIED_LISTEN_INTERVAL_TOO_LARGE => {
                Self::AssocDeniedListenIntervalTooLarge
            }
            IEEE_STATUS_INVALID_FT_ACTION_FRAME_COUNT => {
                Self::InvalidFtActionFrameCount
            }
            IEEE_STATUS_INVALID_PMKID => Self::InvalidPmkid,
            IEEE_STATUS_INVALID_MDE => Self::InvalidMde,
            IEEE_STATUS_INVALID_FTE => Self::InvalidFte,
            IEEE_REQUESTED_TCLAS_NOT_SUPPORTED => {
                Self::RequestedTclasNotSupported
            }
            IEEE_INSUFFICIENT_TCLAS_PROCESSING_RESOURCES => {
                Self::InsufficientTclasProcessingResources
            }
            IEEE_TRY_ANOTHER_BSS => Self::TryAnotherBss,
            IEEE_GAS_ADVERTISEMENT_PROTOCOL_NOT_SUPPORTED => {
                Self::GasAdvertisementProtocolNotSupported
            }
            IEEE_NO_OUTSTANDING_GAS_REQUEST => Self::NoOutstandingGasRequest,
            IEEE_GAS_RESPONSE_NOT_RECEIVED_FROM_SERVER => {
                Self::GasResponseNotReceived
            }
            IEEE_GAS_QUERY_TIMEOUT => Self::GasQueryTimeout,
            IEEE_GAS_QUERY_RESPONSE_TOO_LARGE => Self::GasQueryResponseTooLarge,
            IEEE_REJECTED_HOME_WITH_SUGGESTED_CHANGES => {
                Self::RejectedHomeWithSuggestedChanges
            }
            IEEE_SERVER_UNREACHABLE => Self::ServerUnreachable,
            IEEE_REJECTED_FOR_SSP_PERMISSIONS => {
                Self::RejectedForSspPermissions
            }
            IEEE_REFUSED_UNAUTHENTICATED_ACCESS_NOT_SUPPORTED => {
                Self::RefusedUnauthenticatedAccessNotSupported
            }
            IEEE_INVALID_RSNE => Self::InvalidRsne,
            IEEE_U_APSD_COEXISTENCE_NOT_SUPPORTED => {
                Self::UapsdCoexistenceNotSupported
            }
            IEEE_U_APSD_COEX_MODE_NOT_SUPPORTED => {
                Self::UapsdCoexModeNotSupported
            }
            IEEE_BAD_INTERVAL_WITH_U_APSD_COEX => {
                Self::BadIntervalWithUapsdCoex
            }
            IEEE_ANTI_CLOGGING_TOKEN_REQUIRED => Self::AntiClogRequired,
            IEEE_UNSUPPORTED_FINITE_CYCLIC_GROUP => {
                Self::UnsupportedFiniteCyclicGroup
            }
            IEEE_CANNOT_FIND_ALTERNATIVE_TBTT => {
                Self::CannotFindAlternativeTbtt
            }
            IEEE_TRANSMISSION_FAILURE => Self::TransmissionFailure,
            IEEE_TCLAS_RESOURCES_EXHAUSTED => Self::TclasResourcesExhausted,
            IEEE_REJECTED_WITH_SUGGESTED_BSS_TRANSITION => {
                Self::RejectedWithSuggestedBssTransition
            }
            IEEE_REJECT_WITH_SCHEDULE => Self::RejectWithSchedule,
            IEEE_REJECT_NO_WAKEUP_SPECIFIED => Self::RejectNoWakeupSpecified,
            IEEE_SUCCESS_POWER_SAVE_MODE => Self::SuccessPowerSaveMode,
            IEEE_PENDING_ADMITTING_FST_SESSION => {
                Self::PendingAdmittingFstSession
            }
            IEEE_PERFORMING_FST_NOW => Self::PerformingFstNow,
            IEEE_PENDING_GAP_IN_BA_WINDOW => Self::PendingGapInBaWindow,
            IEEE_REJECT_U_PID_SETTING => Self::RejectUPidSetting,
            IEEE_REFUSED_EXTERNAL_REASON => Self::RefusedExternalReason,
            IEEE_REFUSED_AP_OUT_OF_MEMORY => Self::RefusedApOutOfMemory,
            IEEE_REJECTED_EMERGENCY_SERVICES_NOT_SUPPORTED => {
                Self::RejectedEmergencyServicesNotSupported
            }
            IEEE_QUERY_RESPONSE_OUTSTANDING => Self::QueryResponseOutstanding,
            IEEE_REJECT_DSE_BAND => Self::RejectDseBand,
            IEEE_TCLAS_PROCESSING_TERMINATED => Self::TclasProcessingTerminated,
            IEEE_TS_SCHEDULE_CONFLICT => Self::TsScheduleConflict,
            IEEE_DENIED_WITH_SUGGESTED_BAND_AND_CHANNEL => {
                Self::DeniedWithSuggestedBandAndChannel
            }
            IEEE_MCCAOP_RESERVATION_CONFLICT => Self::McaopReservationConflict,
            IEEE_MAF_LIMIT_EXCEEDED => Self::MafLimitExceeded,
            IEEE_MCCA_TRACK_LIMIT_EXCEEDED => Self::McaTrackLimitExceeded,
            IEEE_DENIED_DUE_TO_SPECTRUM_MANAGEMENT => {
                Self::DeniedDueToSpectrumManagement
            }
            IEEE_DENIED_VHT_NOT_SUPPORTED => Self::DeniedVhtNotSupported,
            IEEE_ENABLEMENT_DENIED => Self::EnablementDenied,
            IEEE_RESTRICTION_FROM_AUTHORIZED_GDB => {
                Self::RestrictionFromAuthorizedGdb
            }
            IEEE_AUTHORIZATION_DEENABLED => Self::AuthorizationDeenabled,
            IEEE_ENERGY_LIMITED_OPERATION_NOT_SUPPORTED => {
                Self::EnergyLimitedOperationNotSupported
            }
            IEEE_REJECTED_NDP_BLOCK_ACK_SUGGESTED => {
                Self::RejectedNdpBlockAckSuggested
            }
            IEEE_REJECTED_MAX_AWAY_DURATION_UNACCEPTABLE => {
                Self::RejectedMaxAwayDurationUnacceptable
            }
            IEEE_FILS_AUTHENTICATION_FAILURE => Self::FilsAuthenticationFailure,
            IEEE_UNKNOWN_AUTHENTICATION_SERVER => {
                Self::UnknownAuthenticationServer
            }
            IEEE_DENIED_NOTIFICATION_PERIOD_ALLOCATION => {
                Self::DeniedNotificationPeriodAllocation
            }
            IEEE_DENIED_CHANNEL_SPLITTING => Self::DeniedChannelSplitting,
            IEEE_DENIED_ALLOCATION => Self::DeniedAllocation,
            IEEE_CMMG_FEATURES_NOT_SUPPORTED => Self::CmmgFeaturesNotSupported,
            IEEE_GAS_FRAGMENT_NOT_AVAILABLE => Self::GasFragmentNotAvailable,
            IEEE_SUCCESS_CAG_VERSIONS_MATCH => Self::SuccessCagVersionsMatch,
            IEEE_GLK_NOT_AUTHORIZED => Self::GlkNotAuthorized,
            IEEE_UNKNOWN_PASSWORD_IDENTIFIER => Self::UnknownPasswordIdentifier,
            IEEE_DENIED_HE_NOT_SUPPORTED => Self::DeniedHeNotSupported,
            IEEE_DENIED_LOCAL_MAC_ADDRESS_POLICY_VIOLATION => {
                Self::DeniedLocalMacAddressNotSupported
            }
            IEEE_SAE_HASH_TO_ELEMENT => Self::SaeHashToElement,
            IEEE_SAE_PK => Self::SaePk,
            IEEE_DENIED_TID_TO_LINK_MAPPING => Self::DeniedTidToLinkMapping,
            IEEE_PREFERRED_TID_TO_LINK_MAPPING_SUGGESTED => {
                Self::PrefTidToLinkMappingSuggested
            }
            IEEE_INVALID_PUBLIC_KEY => Self::InvalidPublicKey,
            IEEE_PASN_BASE_AKMP_FAILED => Self::PasnBaseAkmFailed,
            IEEE_OCI_MISMATCH => Self::OciMismatch,
            IEEE_GAS_QUERY_REQUEST_TOO_LARGE => Self::GasQueryRequestTooLarge,
            IEEE_8021X_AUTH_SUCCESS => Self::Ieee8021xAuthSuccess,
            _ => Self::Other(v),
        }
    }
}

impl std::fmt::Display for Nl80211EventCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Success => f.write_str("success"),
            Self::UnspecifiedFailure => f.write_str("unspecified_failure"),
            Self::TdlsRejectedAlternativeProvided => {
                f.write_str("tdls_rejected_alternative_provided")
            }
            Self::TdlsRejected => f.write_str("tdls_rejected"),
            Self::SecurityDisabled => f.write_str("security_disabled"),
            Self::UnacceptableLifetime => f.write_str("unacceptable_lifetime"),
            Self::NotInSameBss => f.write_str("not_in_same_bss"),
            Self::CapsUnsupported => f.write_str("caps_unsupported"),
            Self::ReassocNoAssoc => f.write_str("reassoc_no_assoc"),
            Self::AssocDeniedUnspec => f.write_str("assoc_denied_unspec"),
            Self::NotSupportedAuthAlg => f.write_str("not_supported_auth_alg"),
            Self::UnknownAuthTransaction => {
                f.write_str("unknown_auth_transaction")
            }
            Self::ChallengeFail => f.write_str("challenge_fail"),
            Self::AuthTimeout => f.write_str("auth_timeout"),
            Self::ApUnableToHandleNewSta => {
                f.write_str("ap_unable_to_handle_new_sta")
            }
            Self::AssocDeniedRates => f.write_str("assoc_denied_rates"),
            Self::AssocDeniedNoShortPreamble => {
                f.write_str("assoc_denied_no_short_preamble")
            }
            Self::AssocDeniedNoPbcc => f.write_str("assoc_denied_no_pbcc"),
            Self::AssocDeniedNoAgility => {
                f.write_str("assoc_denied_no_agility")
            }
            Self::AssocDeniedNoSpectrum => {
                f.write_str("assoc_denied_no_spectrum")
            }
            Self::AssocRejectedBadPower => {
                f.write_str("assoc_rejected_bad_power")
            }
            Self::AssocRejectedBadSuppChan => {
                f.write_str("assoc_rejected_bad_supp_chan")
            }
            Self::AssocDeniedNoShortTime => {
                f.write_str("assoc_denied_no_short_time")
            }
            Self::AssocDeniedNoDsssOfdm => {
                f.write_str("assoc_denied_no_dsss_ofdm")
            }
            Self::DeniedNoHtSupport => f.write_str("denied_no_ht_support"),
            Self::R0khUnreachable => f.write_str("r0kh_unreachable"),
            Self::AssocRejectedTemporarily => {
                f.write_str("assoc_rejected_temporarily")
            }
            Self::RobustMgmtFramePolicyViolation => {
                f.write_str("robust_mgmt_frame_policy_violation")
            }
            Self::UnspecifiedQos => f.write_str("unspecified_qos"),
            Self::AssocDeniedNoBandwidth => {
                f.write_str("assoc_denied_no_bandwidth")
            }
            Self::AssocDeniedLowAck => f.write_str("assoc_denied_low_ack"),
            Self::AssocDeniedUnsuppQos => {
                f.write_str("assoc_denied_unsupp_qos")
            }
            Self::RequestDeclined => f.write_str("request_declined"),
            Self::InvalidQosParam => f.write_str("invalid_qos_param"),
            Self::RejectedWithSuggestedChanges => {
                f.write_str("rejected_with_suggested_changes")
            }
            Self::InvalidIe => f.write_str("invalid_ie"),
            Self::InvalidGroupCipher => f.write_str("invalid_group_cipher"),
            Self::InvalidPairwiseCipher => {
                f.write_str("invalid_pairwise_cipher")
            }
            Self::InvalidAkm => f.write_str("invalid_akm"),
            Self::UnsuppRsnVersion => f.write_str("unsupp_rsn_version"),
            Self::InvalidRsnIeCap => f.write_str("invalid_rsn_ie_cap"),
            Self::CipherSuiteRejected => f.write_str("cipher_suite_rejected"),
            Self::RejectedForDelayPeriod => {
                f.write_str("rejected_for_delay_period")
            }
            Self::NoDirectLink => f.write_str("no_direct_link"),
            Self::StaNotPresent => f.write_str("sta_not_present"),
            Self::StaNotQsta => f.write_str("sta_not_qsta"),
            Self::AssocDeniedListenIntervalTooLarge => {
                f.write_str("assoc_denied_listen_interval_too_large")
            }
            Self::InvalidFtActionFrameCount => {
                f.write_str("invalid_ft_action_frame_count")
            }
            Self::InvalidPmkid => f.write_str("invalid_pmkid"),
            Self::InvalidMde => f.write_str("invalid_mde"),
            Self::InvalidFte => f.write_str("invalid_fte"),
            Self::RequestedTclasNotSupported => {
                f.write_str("requested_tclas_not_supported")
            }
            Self::InsufficientTclasProcessingResources => {
                f.write_str("insufficient_tclas_processing_resources")
            }
            Self::TryAnotherBss => f.write_str("try_another_bss"),
            Self::GasAdvertisementProtocolNotSupported => {
                f.write_str("gas_advertisement_protocol_not_supported")
            }
            Self::NoOutstandingGasRequest => {
                f.write_str("no_outstanding_gas_request")
            }
            Self::GasResponseNotReceived => {
                f.write_str("gas_response_not_received")
            }
            Self::GasQueryTimeout => f.write_str("gas_query_timeout"),
            Self::GasQueryResponseTooLarge => {
                f.write_str("gas_query_response_too_large")
            }
            Self::RejectedHomeWithSuggestedChanges => {
                f.write_str("rejected_home_with_suggested_changes")
            }
            Self::ServerUnreachable => f.write_str("server_unreachable"),
            Self::RejectedForSspPermissions => {
                f.write_str("rejected_for_ssp_permissions")
            }
            Self::RefusedUnauthenticatedAccessNotSupported => {
                f.write_str("refused_unauthenticated_access_not_supported")
            }
            Self::InvalidRsne => f.write_str("invalid_rsne"),
            Self::UapsdCoexistenceNotSupported => {
                f.write_str("uapsd_coexistence_not_supported")
            }
            Self::UapsdCoexModeNotSupported => {
                f.write_str("uapsd_coex_mode_not_supported")
            }
            Self::BadIntervalWithUapsdCoex => {
                f.write_str("bad_interval_with_uapsd_coex")
            }
            Self::AntiClogRequired => f.write_str("anti_clog_required"),
            Self::UnsupportedFiniteCyclicGroup => {
                f.write_str("unsupported_finite_cyclic_group")
            }
            Self::CannotFindAlternativeTbtt => {
                f.write_str("cannot_find_alternative_tbtt")
            }
            Self::TransmissionFailure => f.write_str("transmission_failure"),
            Self::TclasResourcesExhausted => {
                f.write_str("tclas_resources_exhausted")
            }
            Self::RejectedWithSuggestedBssTransition => {
                f.write_str("rejected_with_suggested_bss_transition")
            }
            Self::RejectWithSchedule => f.write_str("reject_with_schedule"),
            Self::RejectNoWakeupSpecified => {
                f.write_str("reject_no_wakeup_specified")
            }
            Self::SuccessPowerSaveMode => {
                f.write_str("success_power_save_mode")
            }
            Self::PendingAdmittingFstSession => {
                f.write_str("pending_admitting_fst_session")
            }
            Self::PerformingFstNow => f.write_str("performing_fst_now"),
            Self::PendingGapInBaWindow => {
                f.write_str("pending_gap_in_ba_window")
            }
            Self::RejectUPidSetting => f.write_str("reject_u_pid_setting"),
            Self::RefusedExternalReason => {
                f.write_str("refused_external_reason")
            }
            Self::RefusedApOutOfMemory => {
                f.write_str("refused_ap_out_of_memory")
            }
            Self::RejectedEmergencyServicesNotSupported => {
                f.write_str("rejected_emergency_services_not_supported")
            }
            Self::QueryResponseOutstanding => {
                f.write_str("query_response_outstanding")
            }
            Self::RejectDseBand => f.write_str("reject_dse_band"),
            Self::TclasProcessingTerminated => {
                f.write_str("tclas_processing_terminated")
            }
            Self::TsScheduleConflict => f.write_str("ts_schedule_conflict"),
            Self::DeniedWithSuggestedBandAndChannel => {
                f.write_str("denied_with_suggested_band_and_channel")
            }
            Self::McaopReservationConflict => {
                f.write_str("mcaop_reservation_conflict")
            }
            Self::MafLimitExceeded => f.write_str("maf_limit_exceeded"),
            Self::McaTrackLimitExceeded => {
                f.write_str("mca_track_limit_exceeded")
            }
            Self::DeniedDueToSpectrumManagement => {
                f.write_str("denied_due_to_spectrum_management")
            }
            Self::DeniedVhtNotSupported => {
                f.write_str("denied_vht_not_supported")
            }
            Self::EnablementDenied => f.write_str("enablement_denied"),
            Self::RestrictionFromAuthorizedGdb => {
                f.write_str("restriction_from_authorized_gdb")
            }
            Self::AuthorizationDeenabled => {
                f.write_str("authorization_deenabled")
            }
            Self::EnergyLimitedOperationNotSupported => {
                f.write_str("energy_limited_operation_not_supported")
            }
            Self::RejectedNdpBlockAckSuggested => {
                f.write_str("rejected_ndp_block_ack_suggested")
            }
            Self::RejectedMaxAwayDurationUnacceptable => {
                f.write_str("rejected_max_away_duration_unacceptable")
            }
            Self::FilsAuthenticationFailure => {
                f.write_str("fils_authentication_failure")
            }
            Self::UnknownAuthenticationServer => {
                f.write_str("unknown_authentication_server")
            }
            Self::DeniedNotificationPeriodAllocation => {
                f.write_str("denied_notification_period_allocation")
            }
            Self::DeniedChannelSplitting => {
                f.write_str("denied_channel_splitting")
            }
            Self::DeniedAllocation => f.write_str("denied_allocation"),
            Self::CmmgFeaturesNotSupported => {
                f.write_str("cmmg_features_not_supported")
            }
            Self::GasFragmentNotAvailable => {
                f.write_str("gas_fragment_not_available")
            }
            Self::SuccessCagVersionsMatch => {
                f.write_str("success_cag_versions_match")
            }
            Self::GlkNotAuthorized => f.write_str("glk_not_authorized"),
            Self::UnknownPasswordIdentifier => {
                f.write_str("unknown_password_identifier")
            }
            Self::DeniedHeNotSupported => {
                f.write_str("denied_he_not_supported")
            }
            Self::DeniedLocalMacAddressNotSupported => {
                f.write_str("denied_local_mac_address_not_supported")
            }
            Self::SaeHashToElement => f.write_str("sae_hash_to_element"),
            Self::SaePk => f.write_str("sae_pk"),
            Self::DeniedTidToLinkMapping => {
                f.write_str("denied_tid_to_link_mapping")
            }
            Self::PrefTidToLinkMappingSuggested => {
                f.write_str("pref_tid_to_link_mapping_suggested")
            }
            Self::InvalidPublicKey => f.write_str("invalid_public_key"),
            Self::PasnBaseAkmFailed => f.write_str("pasn_base_akm_failed"),
            Self::OciMismatch => f.write_str("oci_mismatch"),
            Self::GasQueryRequestTooLarge => {
                f.write_str("gas_query_request_too_large")
            }
            Self::Ieee8021xAuthSuccess => f.write_str("ieee8021x_auth_success"),
            Self::Other(d) => write!(f, "{d}"),
        }
    }
}

impl std::str::FromStr for Nl80211EventCode {
    type Err = DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "success" => Ok(Self::Success),
            "unspecified_failure" => Ok(Self::UnspecifiedFailure),
            "tdls_rejected_alternative_provided" => {
                Ok(Self::TdlsRejectedAlternativeProvided)
            }
            "tdls_rejected" => Ok(Self::TdlsRejected),
            "security_disabled" => Ok(Self::SecurityDisabled),
            "unacceptable_lifetime" => Ok(Self::UnacceptableLifetime),
            "not_in_same_bss" => Ok(Self::NotInSameBss),
            "caps_unsupported" => Ok(Self::CapsUnsupported),
            "reassoc_no_assoc" => Ok(Self::ReassocNoAssoc),
            "assoc_denied_unspec" => Ok(Self::AssocDeniedUnspec),
            "not_supported_auth_alg" => Ok(Self::NotSupportedAuthAlg),
            "unknown_auth_transaction" => Ok(Self::UnknownAuthTransaction),
            "challenge_fail" => Ok(Self::ChallengeFail),
            "auth_timeout" => Ok(Self::AuthTimeout),
            "ap_unable_to_handle_new_sta" => Ok(Self::ApUnableToHandleNewSta),
            "assoc_denied_rates" => Ok(Self::AssocDeniedRates),
            "assoc_denied_no_short_preamble" => {
                Ok(Self::AssocDeniedNoShortPreamble)
            }
            "assoc_denied_no_pbcc" => Ok(Self::AssocDeniedNoPbcc),
            "assoc_denied_no_agility" => Ok(Self::AssocDeniedNoAgility),
            "assoc_denied_no_spectrum" => Ok(Self::AssocDeniedNoSpectrum),
            "assoc_rejected_bad_power" => Ok(Self::AssocRejectedBadPower),
            "assoc_rejected_bad_supp_chan" => {
                Ok(Self::AssocRejectedBadSuppChan)
            }
            "assoc_denied_no_short_time" => Ok(Self::AssocDeniedNoShortTime),
            "assoc_denied_no_dsss_ofdm" => Ok(Self::AssocDeniedNoDsssOfdm),
            "denied_no_ht_support" => Ok(Self::DeniedNoHtSupport),
            "r0kh_unreachable" => Ok(Self::R0khUnreachable),
            "assoc_rejected_temporarily" => Ok(Self::AssocRejectedTemporarily),
            "robust_mgmt_frame_policy_violation" => {
                Ok(Self::RobustMgmtFramePolicyViolation)
            }
            "unspecified_qos" => Ok(Self::UnspecifiedQos),
            "assoc_denied_no_bandwidth" => Ok(Self::AssocDeniedNoBandwidth),
            "assoc_denied_low_ack" => Ok(Self::AssocDeniedLowAck),
            "assoc_denied_unsupp_qos" => Ok(Self::AssocDeniedUnsuppQos),
            "request_declined" => Ok(Self::RequestDeclined),
            "invalid_qos_param" => Ok(Self::InvalidQosParam),
            "rejected_with_suggested_changes" => {
                Ok(Self::RejectedWithSuggestedChanges)
            }
            "invalid_ie" => Ok(Self::InvalidIe),
            "invalid_group_cipher" => Ok(Self::InvalidGroupCipher),
            "invalid_pairwise_cipher" => Ok(Self::InvalidPairwiseCipher),
            "invalid_akm" => Ok(Self::InvalidAkm),
            "unsupp_rsn_version" => Ok(Self::UnsuppRsnVersion),
            "invalid_rsn_ie_cap" => Ok(Self::InvalidRsnIeCap),
            "cipher_suite_rejected" => Ok(Self::CipherSuiteRejected),
            "rejected_for_delay_period" => Ok(Self::RejectedForDelayPeriod),
            "no_direct_link" => Ok(Self::NoDirectLink),
            "sta_not_present" => Ok(Self::StaNotPresent),
            "sta_not_qsta" => Ok(Self::StaNotQsta),
            "assoc_denied_listen_interval_too_large" => {
                Ok(Self::AssocDeniedListenIntervalTooLarge)
            }
            "invalid_ft_action_frame_count" => {
                Ok(Self::InvalidFtActionFrameCount)
            }
            "invalid_pmkid" => Ok(Self::InvalidPmkid),
            "invalid_mde" => Ok(Self::InvalidMde),
            "invalid_fte" => Ok(Self::InvalidFte),
            "requested_tclas_not_supported" => {
                Ok(Self::RequestedTclasNotSupported)
            }
            "insufficient_tclas_processing_resources" => {
                Ok(Self::InsufficientTclasProcessingResources)
            }
            "try_another_bss" => Ok(Self::TryAnotherBss),
            "gas_advertisement_protocol_not_supported" => {
                Ok(Self::GasAdvertisementProtocolNotSupported)
            }
            "no_outstanding_gas_request" => Ok(Self::NoOutstandingGasRequest),
            "gas_response_not_received" => Ok(Self::GasResponseNotReceived),
            "gas_query_timeout" => Ok(Self::GasQueryTimeout),
            "gas_query_response_too_large" => {
                Ok(Self::GasQueryResponseTooLarge)
            }
            "rejected_home_with_suggested_changes" => {
                Ok(Self::RejectedHomeWithSuggestedChanges)
            }
            "server_unreachable" => Ok(Self::ServerUnreachable),
            "rejected_for_ssp_permissions" => {
                Ok(Self::RejectedForSspPermissions)
            }
            "refused_unauthenticated_access_not_supported" => {
                Ok(Self::RefusedUnauthenticatedAccessNotSupported)
            }
            "invalid_rsne" => Ok(Self::InvalidRsne),
            "uapsd_coexistence_not_supported" => {
                Ok(Self::UapsdCoexistenceNotSupported)
            }
            "uapsd_coex_mode_not_supported" => {
                Ok(Self::UapsdCoexModeNotSupported)
            }
            "bad_interval_with_uapsd_coex" => {
                Ok(Self::BadIntervalWithUapsdCoex)
            }
            "anti_clog_required" => Ok(Self::AntiClogRequired),
            "unsupported_finite_cyclic_group" => {
                Ok(Self::UnsupportedFiniteCyclicGroup)
            }
            "cannot_find_alternative_tbtt" => {
                Ok(Self::CannotFindAlternativeTbtt)
            }
            "transmission_failure" => Ok(Self::TransmissionFailure),
            "tclas_resources_exhausted" => Ok(Self::TclasResourcesExhausted),
            "rejected_with_suggested_bss_transition" => {
                Ok(Self::RejectedWithSuggestedBssTransition)
            }
            "reject_with_schedule" => Ok(Self::RejectWithSchedule),
            "reject_no_wakeup_specified" => Ok(Self::RejectNoWakeupSpecified),
            "success_power_save_mode" => Ok(Self::SuccessPowerSaveMode),
            "pending_admitting_fst_session" => {
                Ok(Self::PendingAdmittingFstSession)
            }
            "performing_fst_now" => Ok(Self::PerformingFstNow),
            "pending_gap_in_ba_window" => Ok(Self::PendingGapInBaWindow),
            "reject_u_pid_setting" => Ok(Self::RejectUPidSetting),
            "refused_external_reason" => Ok(Self::RefusedExternalReason),
            "refused_ap_out_of_memory" => Ok(Self::RefusedApOutOfMemory),
            "rejected_emergency_services_not_supported" => {
                Ok(Self::RejectedEmergencyServicesNotSupported)
            }
            "query_response_outstanding" => Ok(Self::QueryResponseOutstanding),
            "reject_dse_band" => Ok(Self::RejectDseBand),
            "tclas_processing_terminated" => {
                Ok(Self::TclasProcessingTerminated)
            }
            "ts_schedule_conflict" => Ok(Self::TsScheduleConflict),
            "denied_with_suggested_band_and_channel" => {
                Ok(Self::DeniedWithSuggestedBandAndChannel)
            }
            "mcaop_reservation_conflict" => Ok(Self::McaopReservationConflict),
            "maf_limit_exceeded" => Ok(Self::MafLimitExceeded),
            "mca_track_limit_exceeded" => Ok(Self::McaTrackLimitExceeded),
            "denied_due_to_spectrum_management" => {
                Ok(Self::DeniedDueToSpectrumManagement)
            }
            "denied_vht_not_supported" => Ok(Self::DeniedVhtNotSupported),
            "enablement_denied" => Ok(Self::EnablementDenied),
            "restriction_from_authorized_gdb" => {
                Ok(Self::RestrictionFromAuthorizedGdb)
            }
            "authorization_deenabled" => Ok(Self::AuthorizationDeenabled),
            "energy_limited_operation_not_supported" => {
                Ok(Self::EnergyLimitedOperationNotSupported)
            }
            "rejected_ndp_block_ack_suggested" => {
                Ok(Self::RejectedNdpBlockAckSuggested)
            }
            "rejected_max_away_duration_unacceptable" => {
                Ok(Self::RejectedMaxAwayDurationUnacceptable)
            }
            "fils_authentication_failure" => {
                Ok(Self::FilsAuthenticationFailure)
            }
            "unknown_authentication_server" => {
                Ok(Self::UnknownAuthenticationServer)
            }
            "denied_notification_period_allocation" => {
                Ok(Self::DeniedNotificationPeriodAllocation)
            }
            "denied_channel_splitting" => Ok(Self::DeniedChannelSplitting),
            "denied_allocation" => Ok(Self::DeniedAllocation),
            "cmmg_features_not_supported" => Ok(Self::CmmgFeaturesNotSupported),
            "gas_fragment_not_available" => Ok(Self::GasFragmentNotAvailable),
            "success_cag_versions_match" => Ok(Self::SuccessCagVersionsMatch),
            "glk_not_authorized" => Ok(Self::GlkNotAuthorized),
            "unknown_password_identifier" => {
                Ok(Self::UnknownPasswordIdentifier)
            }
            "denied_he_not_supported" => Ok(Self::DeniedHeNotSupported),
            "denied_local_mac_address_not_supported" => {
                Ok(Self::DeniedLocalMacAddressNotSupported)
            }
            "sae_hash_to_element" => Ok(Self::SaeHashToElement),
            "sae_pk" => Ok(Self::SaePk),
            "denied_tid_to_link_mapping" => Ok(Self::DeniedTidToLinkMapping),
            "pref_tid_to_link_mapping_suggested" => {
                Ok(Self::PrefTidToLinkMappingSuggested)
            }
            "invalid_public_key" => Ok(Self::InvalidPublicKey),
            "pasn_base_akm_failed" => Ok(Self::PasnBaseAkmFailed),
            "oci_mismatch" => Ok(Self::OciMismatch),
            "gas_query_request_too_large" => Ok(Self::GasQueryRequestTooLarge),
            "ieee8021x_auth_success" => Ok(Self::Ieee8021xAuthSuccess),
            _ => s.parse::<u16>().map(Self::from).map_err(|_| {
                DecodeError::from(format!("unknown nl80211 event status: {s}"))
            }),
        }
    }
}

/// The reason for a `NL80211_CMD_DISCONNECT` event, from the
/// IEEE 802.11 reason code carried in the event.
///
/// Variants cover the IEEE 802.11-2020/2024 reason code table; the
/// variant name follows the Linux kernel constant (`WLAN_REASON_*`, see
/// `include/linux/ieee80211.h`) when one exists, otherwise the name used
/// by the IEEE standard.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum Nl80211EventReason {
    /// IEEE 802.11 reason code 1.
    Unspecified,
    /// IEEE 802.11 reason code 2.
    PrevAuthNotValid,
    /// IEEE 802.11 reason code 3.
    DeauthLeaving,
    /// IEEE 802.11 reason code 4.
    DisassocDueToInactivity,
    /// IEEE 802.11 reason code 5.
    DisassocApBusy,
    /// IEEE 802.11 reason code 6.
    Class2FrameFromNonAuthSta,
    /// IEEE 802.11 reason code 7.
    Class3FrameFromNonAssocSta,
    /// IEEE 802.11 reason code 8.
    DisassocStaHasLeft,
    /// IEEE 802.11 reason code 9.
    StaReqAssocWithoutAuth,
    /// IEEE 802.11 reason code 10.
    DisassocBadPower,
    /// IEEE 802.11 reason code 11.
    DisassocBadSuppChan,
    /// IEEE 802.11 reason code 12.
    BssTransitionDisassoc,
    /// IEEE 802.11 reason code 13.
    InvalidIe,
    /// IEEE 802.11 reason code 14.
    MicFailure,
    /// IEEE 802.11 reason code 15.
    FourWayHandshakeTimeout,
    /// IEEE 802.11 reason code 16.
    GroupKeyHandshakeTimeout,
    /// IEEE 802.11 reason code 17.
    IeDifferent,
    /// IEEE 802.11 reason code 18.
    InvalidGroupCipher,
    /// IEEE 802.11 reason code 19.
    InvalidPairwiseCipher,
    /// IEEE 802.11 reason code 20.
    InvalidAkm,
    /// IEEE 802.11 reason code 21.
    UnsuppRsnVersion,
    /// IEEE 802.11 reason code 22.
    InvalidRsnIeCap,
    /// IEEE 802.11 reason code 23.
    Ieee8021xFailed,
    /// IEEE 802.11 reason code 24.
    CipherSuiteRejected,
    /// IEEE 802.11 reason code 25.
    TdlsTeardownUnreachable,
    /// IEEE 802.11 reason code 26.
    TdlsTeardownUnspecified,
    /// IEEE 802.11 reason code 27.
    SspRequestedDisassoc,
    /// IEEE 802.11 reason code 28.
    NoSspRoamingAgreement,
    /// IEEE 802.11 reason code 29.
    BadCipherOrAkm,
    /// IEEE 802.11 reason code 30.
    NotAuthorizedThisLocation,
    /// IEEE 802.11 reason code 31.
    ServiceChangePrecludesTs,
    /// IEEE 802.11 reason code 32.
    DisassocUnspecifiedQos,
    /// IEEE 802.11 reason code 33.
    DisassocQapNoBandwidth,
    /// IEEE 802.11 reason code 34.
    DisassocLowAck,
    /// IEEE 802.11 reason code 35.
    DisassocQapExceedTxop,
    /// IEEE 802.11 reason code 36.
    QstaLeaveQbss,
    /// IEEE 802.11 reason code 37.
    QstaNotUse,
    /// IEEE 802.11 reason code 38.
    QstaRequireSetup,
    /// IEEE 802.11 reason code 39.
    QstaTimeout,
    /// IEEE 802.11 reason code 45.
    QstaCipherNotSupp,
    /// IEEE 802.11 reason code 46.
    PeerInitiated,
    /// IEEE 802.11 reason code 47.
    ApInitiated,
    /// IEEE 802.11 reason code 48.
    InvalidFtActionFrameCount,
    /// IEEE 802.11 reason code 49.
    ReasonInvalidPmkid,
    /// IEEE 802.11 reason code 50.
    ReasonInvalidMde,
    /// IEEE 802.11 reason code 51.
    ReasonInvalidFte,
    /// IEEE 802.11 reason code 52.
    MeshPeerCanceled,
    /// IEEE 802.11 reason code 53.
    MeshMaxPeers,
    /// IEEE 802.11 reason code 54.
    MeshConfig,
    /// IEEE 802.11 reason code 55.
    MeshClose,
    /// IEEE 802.11 reason code 56.
    MeshMaxRetries,
    /// IEEE 802.11 reason code 57.
    MeshConfirmTimeout,
    /// IEEE 802.11 reason code 58.
    MeshInvalidGtk,
    /// IEEE 802.11 reason code 59.
    MeshInconsistentParam,
    /// IEEE 802.11 reason code 60.
    MeshInvalidSecurity,
    /// IEEE 802.11 reason code 61.
    MeshPathError,
    /// IEEE 802.11 reason code 62.
    MeshPathNoForward,
    /// IEEE 802.11 reason code 63.
    MeshPathDestUnreachable,
    /// IEEE 802.11 reason code 64.
    MacExistsInMbss,
    /// IEEE 802.11 reason code 65.
    MeshChanRegulatory,
    /// IEEE 802.11 reason code 66.
    MeshChan,
    /// IEEE 802.11 reason code 67.
    TransmissionLinkEstablishmentFailed,
    /// IEEE 802.11 reason code 68.
    AlternativeChannelOccupied,
    /// IEEE 802.11 reason code 69.
    TimeSyncLost,
    /// IEEE 802.11 reason code 71.
    PoorRssiConditions,
    /// Any reason code not listed above; the raw code is kept.
    Other(u16),
}

/// IEEE 802.11 reason codes, named after the IEEE 802.11-2020/2024 standard.
/// (`IEEE_*`)
const IEEE_UNSPECIFIED_REASON: u16 = 1;
const IEEE_INVALID_AUTHENTICATION: u16 = 2;
const IEEE_LEAVING_NETWORK_DEAUTH: u16 = 3;
const IEEE_REASON_INACTIVITY: u16 = 4;
const IEEE_NO_MORE_STAS: u16 = 5;
const IEEE_INVALID_CLASS2_FRAME: u16 = 6;
const IEEE_INVALID_CLASS3_FRAME: u16 = 7;
const IEEE_LEAVING_NETWORK_DISASS: u16 = 8;
const IEEE_NOT_AUTHENTICATED: u16 = 9;
const IEEE_UNACCEPTABLE_POWER_CAPABILITY: u16 = 10;
const IEEE_UNACCEPTABLE_SUPPORTED_CHANNELS: u16 = 11;
const IEEE_BSS_TRANSITION_DISASSOC: u16 = 12;
const IEEE_REASON_INVALID_ELEMENT: u16 = 13;
const IEEE_MIC_FAILURE: u16 = 14;
const IEEE_4WAY_HANDSHAKE_TIMEOUT: u16 = 15;
const IEEE_GK_HANDSHAKE_TIMEOUT: u16 = 16;
const IEEE_HANDSHAKE_ELEMENT_MISMATCH: u16 = 17;
const IEEE_REASON_INVALID_GROUP_CIPHER: u16 = 18;
const IEEE_REASON_INVALID_PAIRWISE_CIPHER: u16 = 19;
const IEEE_REASON_INVALID_AKMP: u16 = 20;
const IEEE_REASON_UNSUPPORTED_RSNE_VERSION: u16 = 21;
const IEEE_REASON_INVALID_RSNE_CAPABILITIES: u16 = 22;
const IEEE_802_1_X_AUTH_FAILED: u16 = 23;
const IEEE_REASON_CIPHER_OUT_OF_POLICY: u16 = 24;
const IEEE_TDLS_PEER_UNREACHABLE: u16 = 25;
const IEEE_TDLS_UNSPECIFIED_REASON: u16 = 26;
const IEEE_SSP_REQUESTED_DISASSOC: u16 = 27;
const IEEE_NO_SSP_ROAMING_AGREEMENT: u16 = 28;
const IEEE_BAD_CIPHER_OR_AKM: u16 = 29;
const IEEE_NOT_AUTHORIZED_THIS_LOCATION: u16 = 30;
const IEEE_SERVICE_CHANGE_PRECLUDES_TS: u16 = 31;
const IEEE_UNSPECIFIED_QOS_REASON: u16 = 32;
const IEEE_DISASSOC_QAP_NO_BANDWIDTH: u16 = 33;
const IEEE_MISSING_ACKS: u16 = 34;
const IEEE_EXCEEDED_TXOP: u16 = 35;
const IEEE_STA_LEAVING: u16 = 36;
const IEEE_END_TS: u16 = 37;
const IEEE_UNKNOWN_TS: u16 = 38;
const IEEE_TIMEOUT: u16 = 39;
const IEEE_QSTA_CIPHER_NOT_SUPP: u16 = 45;
const IEEE_PEER_INITIATED: u16 = 46;
const IEEE_AP_INITIATED: u16 = 47;
const IEEE_INVALID_FT_ACTION_FRAME_COUNT: u16 = 48;
const IEEE_REASON_INVALID_PMKID: u16 = 49;
const IEEE_REASON_INVALID_MDE: u16 = 50;
const IEEE_REASON_INVALID_FTE: u16 = 51;
const IEEE_MESH_PEERING_CANCELED: u16 = 52;
const IEEE_MESH_MAX_PEERS: u16 = 53;
const IEEE_MESH_CONFIGURATION_POLICY_VIOLATION: u16 = 54;
const IEEE_MESH_CLOSE_RCVD: u16 = 55;
const IEEE_MESH_MAX_RETRIES: u16 = 56;
const IEEE_MESH_CONFIRM_TIMEOUT: u16 = 57;
const IEEE_MESH_INVALID_GTK: u16 = 58;
const IEEE_MESH_INCONSISTENT_PARAMETERS: u16 = 59;
const IEEE_MESH_INVALID_SECURITY_CAPABILITY: u16 = 60;
const IEEE_MESH_PATH_ERROR_NO_PROXY_INFORMATION: u16 = 61;
const IEEE_MESH_PATH_ERROR_NO_FORWARDING_INFORMATION: u16 = 62;
const IEEE_MESH_PATH_ERROR_DEST_UNREACHABLE: u16 = 63;
const IEEE_MAC_ADDRESS_ALREADY_EXISTS_IN_MBSS: u16 = 64;
const IEEE_MESH_CHANNEL_SWITCH_REGULATORY_REQUIREMENTS: u16 = 65;
const IEEE_MESH_CHANNEL_SWITCH_UNSPECIFIED: u16 = 66;
const IEEE_TRANSMISSION_LINK_ESTABLISHMENT_FAILED: u16 = 67;
const IEEE_ALTERNATIVE_CHANNEL_OCCUPIED: u16 = 68;
const IEEE_TIME_SYNC_LOST: u16 = 69;
const IEEE_POOR_RSSI_CONDITIONS: u16 = 71;

impl From<u16> for Nl80211EventReason {
    fn from(v: u16) -> Self {
        match v {
            IEEE_UNSPECIFIED_REASON => Self::Unspecified,
            IEEE_INVALID_AUTHENTICATION => Self::PrevAuthNotValid,
            IEEE_LEAVING_NETWORK_DEAUTH => Self::DeauthLeaving,
            IEEE_REASON_INACTIVITY => Self::DisassocDueToInactivity,
            IEEE_NO_MORE_STAS => Self::DisassocApBusy,
            IEEE_INVALID_CLASS2_FRAME => Self::Class2FrameFromNonAuthSta,
            IEEE_INVALID_CLASS3_FRAME => Self::Class3FrameFromNonAssocSta,
            IEEE_LEAVING_NETWORK_DISASS => Self::DisassocStaHasLeft,
            IEEE_NOT_AUTHENTICATED => Self::StaReqAssocWithoutAuth,
            IEEE_UNACCEPTABLE_POWER_CAPABILITY => Self::DisassocBadPower,
            IEEE_UNACCEPTABLE_SUPPORTED_CHANNELS => Self::DisassocBadSuppChan,
            IEEE_BSS_TRANSITION_DISASSOC => Self::BssTransitionDisassoc,
            IEEE_REASON_INVALID_ELEMENT => Self::InvalidIe,
            IEEE_MIC_FAILURE => Self::MicFailure,
            IEEE_4WAY_HANDSHAKE_TIMEOUT => Self::FourWayHandshakeTimeout,
            IEEE_GK_HANDSHAKE_TIMEOUT => Self::GroupKeyHandshakeTimeout,
            IEEE_HANDSHAKE_ELEMENT_MISMATCH => Self::IeDifferent,
            IEEE_REASON_INVALID_GROUP_CIPHER => Self::InvalidGroupCipher,
            IEEE_REASON_INVALID_PAIRWISE_CIPHER => Self::InvalidPairwiseCipher,
            IEEE_REASON_INVALID_AKMP => Self::InvalidAkm,
            IEEE_REASON_UNSUPPORTED_RSNE_VERSION => Self::UnsuppRsnVersion,
            IEEE_REASON_INVALID_RSNE_CAPABILITIES => Self::InvalidRsnIeCap,
            IEEE_802_1_X_AUTH_FAILED => Self::Ieee8021xFailed,
            IEEE_REASON_CIPHER_OUT_OF_POLICY => Self::CipherSuiteRejected,
            IEEE_TDLS_PEER_UNREACHABLE => Self::TdlsTeardownUnreachable,
            IEEE_TDLS_UNSPECIFIED_REASON => Self::TdlsTeardownUnspecified,
            IEEE_SSP_REQUESTED_DISASSOC => Self::SspRequestedDisassoc,
            IEEE_NO_SSP_ROAMING_AGREEMENT => Self::NoSspRoamingAgreement,
            IEEE_BAD_CIPHER_OR_AKM => Self::BadCipherOrAkm,
            IEEE_NOT_AUTHORIZED_THIS_LOCATION => {
                Self::NotAuthorizedThisLocation
            }
            IEEE_SERVICE_CHANGE_PRECLUDES_TS => Self::ServiceChangePrecludesTs,
            IEEE_UNSPECIFIED_QOS_REASON => Self::DisassocUnspecifiedQos,
            IEEE_DISASSOC_QAP_NO_BANDWIDTH => Self::DisassocQapNoBandwidth,
            IEEE_MISSING_ACKS => Self::DisassocLowAck,
            IEEE_EXCEEDED_TXOP => Self::DisassocQapExceedTxop,
            IEEE_STA_LEAVING => Self::QstaLeaveQbss,
            IEEE_END_TS => Self::QstaNotUse,
            IEEE_UNKNOWN_TS => Self::QstaRequireSetup,
            IEEE_TIMEOUT => Self::QstaTimeout,
            IEEE_QSTA_CIPHER_NOT_SUPP => Self::QstaCipherNotSupp,
            IEEE_PEER_INITIATED => Self::PeerInitiated,
            IEEE_AP_INITIATED => Self::ApInitiated,
            IEEE_INVALID_FT_ACTION_FRAME_COUNT => {
                Self::InvalidFtActionFrameCount
            }
            IEEE_REASON_INVALID_PMKID => Self::ReasonInvalidPmkid,
            IEEE_REASON_INVALID_MDE => Self::ReasonInvalidMde,
            IEEE_REASON_INVALID_FTE => Self::ReasonInvalidFte,
            IEEE_MESH_PEERING_CANCELED => Self::MeshPeerCanceled,
            IEEE_MESH_MAX_PEERS => Self::MeshMaxPeers,
            IEEE_MESH_CONFIGURATION_POLICY_VIOLATION => Self::MeshConfig,
            IEEE_MESH_CLOSE_RCVD => Self::MeshClose,
            IEEE_MESH_MAX_RETRIES => Self::MeshMaxRetries,
            IEEE_MESH_CONFIRM_TIMEOUT => Self::MeshConfirmTimeout,
            IEEE_MESH_INVALID_GTK => Self::MeshInvalidGtk,
            IEEE_MESH_INCONSISTENT_PARAMETERS => Self::MeshInconsistentParam,
            IEEE_MESH_INVALID_SECURITY_CAPABILITY => Self::MeshInvalidSecurity,
            IEEE_MESH_PATH_ERROR_NO_PROXY_INFORMATION => Self::MeshPathError,
            IEEE_MESH_PATH_ERROR_NO_FORWARDING_INFORMATION => {
                Self::MeshPathNoForward
            }
            IEEE_MESH_PATH_ERROR_DEST_UNREACHABLE => {
                Self::MeshPathDestUnreachable
            }
            IEEE_MAC_ADDRESS_ALREADY_EXISTS_IN_MBSS => Self::MacExistsInMbss,
            IEEE_MESH_CHANNEL_SWITCH_REGULATORY_REQUIREMENTS => {
                Self::MeshChanRegulatory
            }
            IEEE_MESH_CHANNEL_SWITCH_UNSPECIFIED => Self::MeshChan,
            IEEE_TRANSMISSION_LINK_ESTABLISHMENT_FAILED => {
                Self::TransmissionLinkEstablishmentFailed
            }
            IEEE_ALTERNATIVE_CHANNEL_OCCUPIED => {
                Self::AlternativeChannelOccupied
            }
            IEEE_TIME_SYNC_LOST => Self::TimeSyncLost,
            IEEE_POOR_RSSI_CONDITIONS => Self::PoorRssiConditions,
            _ => Self::Other(v),
        }
    }
}

impl std::fmt::Display for Nl80211EventReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unspecified => f.write_str("unspecified"),
            Self::PrevAuthNotValid => f.write_str("prev_auth_not_valid"),
            Self::DeauthLeaving => f.write_str("deauth_leaving"),
            Self::DisassocDueToInactivity => {
                f.write_str("disassoc_due_to_inactivity")
            }
            Self::DisassocApBusy => f.write_str("disassoc_ap_busy"),
            Self::Class2FrameFromNonAuthSta => {
                f.write_str("class2_frame_from_non_auth_sta")
            }
            Self::Class3FrameFromNonAssocSta => {
                f.write_str("class3_frame_from_non_assoc_sta")
            }
            Self::DisassocStaHasLeft => f.write_str("disassoc_sta_has_left"),
            Self::StaReqAssocWithoutAuth => {
                f.write_str("sta_req_assoc_without_auth")
            }
            Self::DisassocBadPower => f.write_str("disassoc_bad_power"),
            Self::DisassocBadSuppChan => f.write_str("disassoc_bad_supp_chan"),
            Self::BssTransitionDisassoc => {
                f.write_str("bss_transition_disassoc")
            }
            Self::InvalidIe => f.write_str("invalid_ie"),
            Self::MicFailure => f.write_str("mic_failure"),
            Self::FourWayHandshakeTimeout => {
                f.write_str("four_way_handshake_timeout")
            }
            Self::GroupKeyHandshakeTimeout => {
                f.write_str("group_key_handshake_timeout")
            }
            Self::IeDifferent => f.write_str("ie_different"),
            Self::InvalidGroupCipher => f.write_str("invalid_group_cipher"),
            Self::InvalidPairwiseCipher => {
                f.write_str("invalid_pairwise_cipher")
            }
            Self::InvalidAkm => f.write_str("invalid_akm"),
            Self::UnsuppRsnVersion => f.write_str("unsupp_rsn_version"),
            Self::InvalidRsnIeCap => f.write_str("invalid_rsn_ie_cap"),
            Self::Ieee8021xFailed => f.write_str("ieee8021x_failed"),
            Self::CipherSuiteRejected => f.write_str("cipher_suite_rejected"),
            Self::TdlsTeardownUnreachable => {
                f.write_str("tdls_teardown_unreachable")
            }
            Self::TdlsTeardownUnspecified => {
                f.write_str("tdls_teardown_unspecified")
            }
            Self::SspRequestedDisassoc => f.write_str("ssp_requested_disassoc"),
            Self::NoSspRoamingAgreement => {
                f.write_str("no_ssp_roaming_agreement")
            }
            Self::BadCipherOrAkm => f.write_str("bad_cipher_or_akm"),
            Self::NotAuthorizedThisLocation => {
                f.write_str("not_authorized_this_location")
            }
            Self::ServiceChangePrecludesTs => {
                f.write_str("service_change_precludes_ts")
            }
            Self::DisassocUnspecifiedQos => {
                f.write_str("disassoc_unspecified_qos")
            }
            Self::DisassocQapNoBandwidth => {
                f.write_str("disassoc_qap_no_bandwidth")
            }
            Self::DisassocLowAck => f.write_str("disassoc_low_ack"),
            Self::DisassocQapExceedTxop => {
                f.write_str("disassoc_qap_exceed_txop")
            }
            Self::QstaLeaveQbss => f.write_str("qsta_leave_qbss"),
            Self::QstaNotUse => f.write_str("qsta_not_use"),
            Self::QstaRequireSetup => f.write_str("qsta_require_setup"),
            Self::QstaTimeout => f.write_str("qsta_timeout"),
            Self::QstaCipherNotSupp => f.write_str("qsta_cipher_not_supp"),
            Self::PeerInitiated => f.write_str("peer_initiated"),
            Self::ApInitiated => f.write_str("ap_initiated"),
            Self::InvalidFtActionFrameCount => {
                f.write_str("invalid_ft_action_frame_count")
            }
            Self::ReasonInvalidPmkid => f.write_str("reason_invalid_pmkid"),
            Self::ReasonInvalidMde => f.write_str("reason_invalid_mde"),
            Self::ReasonInvalidFte => f.write_str("reason_invalid_fte"),
            Self::MeshPeerCanceled => f.write_str("mesh_peer_canceled"),
            Self::MeshMaxPeers => f.write_str("mesh_max_peers"),
            Self::MeshConfig => f.write_str("mesh_config"),
            Self::MeshClose => f.write_str("mesh_close"),
            Self::MeshMaxRetries => f.write_str("mesh_max_retries"),
            Self::MeshConfirmTimeout => f.write_str("mesh_confirm_timeout"),
            Self::MeshInvalidGtk => f.write_str("mesh_invalid_gtk"),
            Self::MeshInconsistentParam => {
                f.write_str("mesh_inconsistent_param")
            }
            Self::MeshInvalidSecurity => f.write_str("mesh_invalid_security"),
            Self::MeshPathError => f.write_str("mesh_path_error"),
            Self::MeshPathNoForward => f.write_str("mesh_path_no_forward"),
            Self::MeshPathDestUnreachable => {
                f.write_str("mesh_path_dest_unreachable")
            }
            Self::MacExistsInMbss => f.write_str("mac_exists_in_mbss"),
            Self::MeshChanRegulatory => f.write_str("mesh_chan_regulatory"),
            Self::MeshChan => f.write_str("mesh_chan"),
            Self::TransmissionLinkEstablishmentFailed => {
                f.write_str("transmission_link_establishment_failed")
            }
            Self::AlternativeChannelOccupied => {
                f.write_str("alternative_channel_occupied")
            }
            Self::TimeSyncLost => f.write_str("time_sync_lost"),
            Self::PoorRssiConditions => f.write_str("poor_rssi_conditions"),
            Self::Other(d) => write!(f, "{d}"),
        }
    }
}

impl std::str::FromStr for Nl80211EventReason {
    type Err = DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "unspecified" => Ok(Self::Unspecified),
            "prev_auth_not_valid" => Ok(Self::PrevAuthNotValid),
            "deauth_leaving" => Ok(Self::DeauthLeaving),
            "disassoc_due_to_inactivity" => Ok(Self::DisassocDueToInactivity),
            "disassoc_ap_busy" => Ok(Self::DisassocApBusy),
            "class2_frame_from_non_auth_sta" => {
                Ok(Self::Class2FrameFromNonAuthSta)
            }
            "class3_frame_from_non_assoc_sta" => {
                Ok(Self::Class3FrameFromNonAssocSta)
            }
            "disassoc_sta_has_left" => Ok(Self::DisassocStaHasLeft),
            "sta_req_assoc_without_auth" => Ok(Self::StaReqAssocWithoutAuth),
            "disassoc_bad_power" => Ok(Self::DisassocBadPower),
            "disassoc_bad_supp_chan" => Ok(Self::DisassocBadSuppChan),
            "bss_transition_disassoc" => Ok(Self::BssTransitionDisassoc),
            "invalid_ie" => Ok(Self::InvalidIe),
            "mic_failure" => Ok(Self::MicFailure),
            "four_way_handshake_timeout" => Ok(Self::FourWayHandshakeTimeout),
            "group_key_handshake_timeout" => Ok(Self::GroupKeyHandshakeTimeout),
            "ie_different" => Ok(Self::IeDifferent),
            "invalid_group_cipher" => Ok(Self::InvalidGroupCipher),
            "invalid_pairwise_cipher" => Ok(Self::InvalidPairwiseCipher),
            "invalid_akm" => Ok(Self::InvalidAkm),
            "unsupp_rsn_version" => Ok(Self::UnsuppRsnVersion),
            "invalid_rsn_ie_cap" => Ok(Self::InvalidRsnIeCap),
            "ieee8021x_failed" => Ok(Self::Ieee8021xFailed),
            "cipher_suite_rejected" => Ok(Self::CipherSuiteRejected),
            "tdls_teardown_unreachable" => Ok(Self::TdlsTeardownUnreachable),
            "tdls_teardown_unspecified" => Ok(Self::TdlsTeardownUnspecified),
            "ssp_requested_disassoc" => Ok(Self::SspRequestedDisassoc),
            "no_ssp_roaming_agreement" => Ok(Self::NoSspRoamingAgreement),
            "bad_cipher_or_akm" => Ok(Self::BadCipherOrAkm),
            "not_authorized_this_location" => {
                Ok(Self::NotAuthorizedThisLocation)
            }
            "service_change_precludes_ts" => Ok(Self::ServiceChangePrecludesTs),
            "disassoc_unspecified_qos" => Ok(Self::DisassocUnspecifiedQos),
            "disassoc_qap_no_bandwidth" => Ok(Self::DisassocQapNoBandwidth),
            "disassoc_low_ack" => Ok(Self::DisassocLowAck),
            "disassoc_qap_exceed_txop" => Ok(Self::DisassocQapExceedTxop),
            "qsta_leave_qbss" => Ok(Self::QstaLeaveQbss),
            "qsta_not_use" => Ok(Self::QstaNotUse),
            "qsta_require_setup" => Ok(Self::QstaRequireSetup),
            "qsta_timeout" => Ok(Self::QstaTimeout),
            "qsta_cipher_not_supp" => Ok(Self::QstaCipherNotSupp),
            "peer_initiated" => Ok(Self::PeerInitiated),
            "ap_initiated" => Ok(Self::ApInitiated),
            "invalid_ft_action_frame_count" => {
                Ok(Self::InvalidFtActionFrameCount)
            }
            "reason_invalid_pmkid" => Ok(Self::ReasonInvalidPmkid),
            "reason_invalid_mde" => Ok(Self::ReasonInvalidMde),
            "reason_invalid_fte" => Ok(Self::ReasonInvalidFte),
            "mesh_peer_canceled" => Ok(Self::MeshPeerCanceled),
            "mesh_max_peers" => Ok(Self::MeshMaxPeers),
            "mesh_config" => Ok(Self::MeshConfig),
            "mesh_close" => Ok(Self::MeshClose),
            "mesh_max_retries" => Ok(Self::MeshMaxRetries),
            "mesh_confirm_timeout" => Ok(Self::MeshConfirmTimeout),
            "mesh_invalid_gtk" => Ok(Self::MeshInvalidGtk),
            "mesh_inconsistent_param" => Ok(Self::MeshInconsistentParam),
            "mesh_invalid_security" => Ok(Self::MeshInvalidSecurity),
            "mesh_path_error" => Ok(Self::MeshPathError),
            "mesh_path_no_forward" => Ok(Self::MeshPathNoForward),
            "mesh_path_dest_unreachable" => Ok(Self::MeshPathDestUnreachable),
            "mac_exists_in_mbss" => Ok(Self::MacExistsInMbss),
            "mesh_chan_regulatory" => Ok(Self::MeshChanRegulatory),
            "mesh_chan" => Ok(Self::MeshChan),
            "transmission_link_establishment_failed" => {
                Ok(Self::TransmissionLinkEstablishmentFailed)
            }
            "alternative_channel_occupied" => {
                Ok(Self::AlternativeChannelOccupied)
            }
            "time_sync_lost" => Ok(Self::TimeSyncLost),
            "poor_rssi_conditions" => Ok(Self::PoorRssiConditions),
            _ => s.parse::<u16>().map(Self::from).map_err(|_| {
                DecodeError::from(format!("unknown nl80211 event reason: {s}"))
            }),
        }
    }
}
