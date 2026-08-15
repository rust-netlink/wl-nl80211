// SPDX-License-Identifier: MIT

use crate::Ieee80211StatusCode;
use netlink_packet_core::DecodeError;

/// IEEE 802.11 authentication algorithm, from the Authentication Algorithm
/// field of an Authentication frame. Values follow the Linux kernel
/// constants (`WLAN_AUTH_*` in `include/linux/ieee80211.h`).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum Ieee80211AuthAlgorithm {
    /// `WLAN_AUTH_OPEN` (0): Open System authentication.
    OpenSystem,
    /// `WLAN_AUTH_SHARED_KEY` (1): Shared Key authentication.
    SharedKey,
    /// `WLAN_AUTH_FT` (2): Fast BSS Transition.
    FastBssTransition,
    /// `WLAN_AUTH_SAE` (3): Simultaneous Authentication of Equals.
    Sae,
    /// `WLAN_AUTH_FILS_SK` (4): FILS shared key authentication.
    FilsSharedKey,
    /// `WLAN_AUTH_FILS_SK_PFS` (5): FILS shared key with PFS.
    FilsSharedKeyPfs,
    /// `WLAN_AUTH_FILS_PK` (6): FILS public key authentication.
    FilsPublicKey,
    /// `WLAN_AUTH_IEEE8021X` (8): IEEE 802.1X authentication.
    Ieee8021x,
    /// `WLAN_AUTH_EPPKE` (9): EPPKE authentication.
    Eppke,
    /// `WLAN_AUTH_LEAP` (128): LEAP authentication.
    Leap,
    /// Any other algorithm; the raw value is kept.
    Other(u16),
}

impl From<u16> for Ieee80211AuthAlgorithm {
    fn from(alg: u16) -> Self {
        match alg {
            WLAN_AUTH_OPEN => Self::OpenSystem,
            WLAN_AUTH_SHARED_KEY => Self::SharedKey,
            WLAN_AUTH_FT => Self::FastBssTransition,
            WLAN_AUTH_SAE => Self::Sae,
            WLAN_AUTH_FILS_SK => Self::FilsSharedKey,
            WLAN_AUTH_FILS_SK_PFS => Self::FilsSharedKeyPfs,
            WLAN_AUTH_FILS_PK => Self::FilsPublicKey,
            WLAN_AUTH_IEEE8021X => Self::Ieee8021x,
            WLAN_AUTH_EPPKE => Self::Eppke,
            WLAN_AUTH_LEAP => Self::Leap,
            _ => Self::Other(alg),
        }
    }
}

/// IEEE 802.11 authentication algorithm field values, named after the Linux
/// kernel constants (`WLAN_AUTH_*`).
const WLAN_AUTH_OPEN: u16 = 0;
const WLAN_AUTH_SHARED_KEY: u16 = 1;
const WLAN_AUTH_FT: u16 = 2;
const WLAN_AUTH_SAE: u16 = 3;
const WLAN_AUTH_FILS_SK: u16 = 4;
const WLAN_AUTH_FILS_SK_PFS: u16 = 5;
const WLAN_AUTH_FILS_PK: u16 = 6;
const WLAN_AUTH_IEEE8021X: u16 = 8;
const WLAN_AUTH_EPPKE: u16 = 9;
const WLAN_AUTH_LEAP: u16 = 128;

/// A parsed IEEE 802.11 Authentication frame body, as delivered in the
/// `NL80211_ATTR_FRAME` of an `NL80211_CMD_AUTHENTICATE` event
/// (IEEE Std 802.11-2024 §9.3.3.11, Table 9-70).
///
/// The fixed fields are the Authentication algorithm number, transaction
/// sequence number and status code; the remaining body holds the
/// challenge text for Open System/Shared Key, or the SAE commit / confirm
/// body for SAE. The 24-byte MAC header (DA/SA/BSSID/sequence, see
/// §9.2.4.3 and §9.2.4.4) is skipped and not modelled here.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct Ieee80211AuthFrame {
    /// Authentication algorithm.
    pub algorithm: Ieee80211AuthAlgorithm,
    /// Authentication transaction sequence number.
    pub transaction: u16,
    /// IEEE 802.11 status code.
    pub status_code: Ieee80211StatusCode,
    /// Remaining frame body after the fixed fields: challenge text, or the
    /// SAE commit / confirm body.
    pub(crate) remains: Vec<u8>,
}

impl Ieee80211AuthFrame {
    /// Parse an Authentication management frame from its raw bytes.
    ///
    /// Returns an error when the frame is shorter than the fixed 30 bytes
    /// (24-byte MAC header + algorithm + transaction + status).
    pub fn parse(data: &[u8]) -> Result<Self, DecodeError> {
        if data.len() < 30 {
            return Err(DecodeError::from(format!(
                "authentication frame too short: {} bytes",
                data.len()
            )));
        }

        Ok(Ieee80211AuthFrame {
            algorithm: Ieee80211AuthAlgorithm::from(u16::from_le_bytes([
                data[24], data[25],
            ])),
            transaction: u16::from_le_bytes([data[26], data[27]]),
            status_code: Ieee80211StatusCode::from(u16::from_le_bytes([
                data[28], data[29],
            ])),
            remains: data[30..].to_vec(),
        })
    }
}

bitflags::bitflags! {
    /// IEEE 802.11 Capability Information field (802.11-2020 §9.4.1.4),
    /// carried by (Re)Association Response frames and Beacon/Probe Response
    /// frames.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Ieee80211CapabilityInfo: u16 {
        const Ess = 0x0001;
        const Ibss = 0x0002;
        const CfPollable = 0x0004;
        const CfPollRequest = 0x0008;
        const Privacy = 0x0010;
        const ShortPreamble = 0x0020;
        const Pbcc = 0x0040;
        const ChannelAgility = 0x0080;
        const SpectrumManagement = 0x0100;
        const Qos = 0x0200;
        const ShortSlotTime = 0x0400;
        const Apsd = 0x0800;
        const RadioMeasurement = 0x1000;
        const DsssOfdm = 0x2000;
        const DelayedBlockAck = 0x4000;
        const ImmediateBlockAck = 0x8000;
    }
}

/// A parsed IEEE 802.11 (Re)Association Response frame body, as delivered
/// in the `NL80211_ATTR_FRAME` of an `NL80211_CMD_ASSOCIATE` event.
///
/// The frame body is (IEEE Std 802.11-2024 §9.3.3.6 Table 9-65 /
/// §9.3.3.8 Table 9-67): Capability Information(2) || Status Code(2) ||
/// AID(2) || Supported Rates ... The AID and the information elements are
/// kept as raw `remains`; Association Response and Reassociation Response
/// share this body layout.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct Ieee80211AssocRespFrame {
    /// Capability information.
    pub capability: Ieee80211CapabilityInfo,
    /// IEEE 802.11 status code.
    pub status_code: Ieee80211StatusCode,
    /// Remaining frame body after the fixed fields: AID(2) followed by the
    /// information elements.
    pub(crate) remains: Vec<u8>,
}

impl Ieee80211AssocRespFrame {
    /// Parse a (Re)Association Response frame from its raw bytes.
    ///
    /// Returns an error when the frame is shorter than the fixed 28 bytes
    /// (24-byte MAC header + capability + status code).
    pub fn parse(data: &[u8]) -> Result<Self, DecodeError> {
        if data.len() < 28 {
            return Err(DecodeError::from(format!(
                "(re)association response frame too short: {} bytes",
                data.len()
            )));
        }

        Ok(Ieee80211AssocRespFrame {
            capability: Ieee80211CapabilityInfo::from_bits_truncate(
                u16::from_le_bytes([data[24], data[25]]),
            ),
            status_code: Ieee80211StatusCode::from(u16::from_le_bytes([
                data[26], data[27],
            ])),
            remains: data[28..].to_vec(),
        })
    }
}
