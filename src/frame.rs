// SPDX-License-Identifier: MIT

use crate::Nl80211EventCode;
use netlink_packet_core::DecodeError;

/// IEEE 802.11 authentication algorithm, from the Authentication Algorithm
/// field of an Authentication frame. Values follow the Linux kernel
/// constants (`WLAN_AUTH_*` in `include/linux/ieee80211.h`).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum Nl80211AuthAlgorithm {
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

impl From<u16> for Nl80211AuthAlgorithm {
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

/// A parsed IEEE 802.11 Authentication management frame, as delivered in the
/// `NL80211_ATTR_FRAME` of an `NL80211_CMD_AUTHENTICATE` event.
///
/// The frame layout is: 24-byte MAC header (frame control, duration, DA/SA/
/// BSSID, sequence control), then the fixed Authentication fields
/// (algorithm, transaction sequence number, status code), then the frame
/// body (challenge text for Open System/Shared Key, or the SAE commit /
/// confirm body for SAE).
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct Nl80211AuthFrame {
    /// Destination address (Addr1).
    pub da: [u8; 6],
    /// Source address (Addr2).
    pub sa: [u8; 6],
    /// BSSID (Addr3).
    pub bssid: [u8; 6],
    /// Sequence number, from the low 12 bits of the sequence control field.
    pub sequence: u16,
    /// Authentication algorithm.
    pub algorithm: Nl80211AuthAlgorithm,
    /// Authentication transaction sequence number.
    pub transaction: u16,
    /// IEEE 802.11 status code of this frame.
    pub status: Nl80211EventCode,
    /// Frame body: challenge text, or the SAE commit / confirm body.
    pub body: Vec<u8>,
}

impl Nl80211AuthFrame {
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

        let sequence_ctrl = u16::from_le_bytes([data[22], data[23]]);
        Ok(Nl80211AuthFrame {
            da: data[4..10].try_into().expect("6-byte DA"),
            sa: data[10..16].try_into().expect("6-byte SA"),
            bssid: data[16..22].try_into().expect("6-byte BSSID"),
            sequence: sequence_ctrl >> 4,
            algorithm: Nl80211AuthAlgorithm::from(u16::from_le_bytes([
                data[24], data[25],
            ])),
            transaction: u16::from_le_bytes([data[26], data[27]]),
            status: Nl80211EventCode::from(u16::from_le_bytes([
                data[28], data[29],
            ])),
            body: data[30..].to_vec(),
        })
    }
}
