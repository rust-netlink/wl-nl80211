// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    parse_u16, DecodeError, Emitable, ErrorContext, Parseable,
};

use crate::Ieee80211StatusCode;

/// IEEE 802.11 authentication algorithm, from the Authentication Algorithm
/// field of an Authentication frame. Values follow the Linux kernel
/// constants (`WLAN_AUTH_*` in `include/linux/ieee80211.h`).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum Ieee80211AuthAlgorithm {
    /// `WLAN_AUTH_OPEN` (0): Open System authentication.
    OpenSystem,
    /// `WLAN_AUTH_SHARED_KEY` (1): Shared Key authentication. This value is
    /// not defined in IEEE 802.11-2024; kept for legacy compatibility.
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
    /// Authentication algorithm number 7: PASN authentication.
    Pasn,
    /// `WLAN_AUTH_IEEE8021X` (8): IEEE 802.1X authentication.
    Ieee8021x,
    /// `WLAN_AUTH_EPPKE` (9): EPPKE authentication.
    Eppke,
    /// `WLAN_AUTH_LEAP` (128): LEAP authentication.
    Leap,
    /// Authentication algorithm number 65 535: vendor specific use.
    VendorSpecific,
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
            WLAN_AUTH_PASN => Self::Pasn,
            WLAN_AUTH_IEEE8021X => Self::Ieee8021x,
            WLAN_AUTH_EPPKE => Self::Eppke,
            WLAN_AUTH_LEAP => Self::Leap,
            WLAN_AUTH_VENDOR_SPECIFIC => Self::VendorSpecific,
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
const WLAN_AUTH_PASN: u16 = 7;
const WLAN_AUTH_IEEE8021X: u16 = 8;
const WLAN_AUTH_EPPKE: u16 = 9;
const WLAN_AUTH_LEAP: u16 = 128;
const WLAN_AUTH_VENDOR_SPECIFIC: u16 = 65_535;

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
    /// IEEE 802.11-2024 §9.4.1.4, Figure 9-140: Capability Information
    /// field (non-DMG STA), carried by (Re)Association Response frames and
    /// Beacon/Probe Response frames.
    ///
    /// Only bits B0, B1, B4, B5 and B8-B13 are defined; bits B2, B3, B6,
    /// B7, B14 and B15 are reserved.
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    #[non_exhaustive]
    pub struct Ieee80211CapabilityInfo: u16 {
        const Ess = 1 << 0;
        const Ibss = 1 << 1;
        const Privacy = 1 << 4;
        const ShortPreamble = 1 << 5;
        const SpectrumManagement = 1 << 8;
        const Qos = 1 << 9;
        const ShortSlotTime = 1 << 10;
        const Apsd = 1 << 11;
        const RadioMeasurement = 1 << 12;
        const Epd = 1 << 13;
        const _ = !0;
    }
}

impl<T: AsRef<[u8]> + ?Sized> Parseable<T> for Ieee80211CapabilityInfo {
    fn parse(buf: &T) -> Result<Self, DecodeError> {
        let buf = buf.as_ref();
        Ok(Self::from_bits_retain(parse_u16(buf).context(format!(
            "Invalid Ieee80211CapabilityInfo payload {buf:?}"
        ))?))
    }
}

impl Ieee80211CapabilityInfo {
    pub const LENGTH: usize = 2;
}

impl Emitable for Ieee80211CapabilityInfo {
    fn buffer_len(&self) -> usize {
        Self::LENGTH
    }

    fn emit(&self, buffer: &mut [u8]) {
        buffer.copy_from_slice(&self.bits().to_ne_bytes())
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
            capability: Ieee80211CapabilityInfo::from_bits_retain(
                u16::from_le_bytes([data[24], data[25]]),
            ),
            status_code: Ieee80211StatusCode::from(u16::from_le_bytes([
                data[26], data[27],
            ])),
            remains: data[28..].to_vec(),
        })
    }
}
