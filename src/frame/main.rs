// SPDX-License-Identifier: MIT

use netlink_packet_core::{DecodeError, Emitable};

use crate::Ieee80211StatusCode;

use super::buffer::{
    auth_frame_buffer_len, emit_auth_frame, parse_auth_frame,
    Ieee80211AuthFrameFixed,
};
use super::eppke::{Ieee80211AuthFrameEppke, WLAN_AUTH_EPPKE};
use super::fils_public_key::{
    Ieee80211AuthFrameFilsPublicKey, WLAN_AUTH_FILS_PK,
};
use super::fils_shared_key::{
    Ieee80211AuthFrameFilsSharedKey, WLAN_AUTH_FILS_SK,
};
use super::fils_shared_key_pfs::{
    Ieee80211AuthFrameFilsSharedKeyPfs, WLAN_AUTH_FILS_SK_PFS,
};
use super::ft::{Ieee80211AuthFrameFastBssTransition, WLAN_AUTH_FT};
use super::ieee8021x::{Ieee80211AuthFrameIeee8021x, WLAN_AUTH_IEEE8021X};
use super::leap::{Ieee80211AuthFrameLeap, WLAN_AUTH_LEAP};
use super::open::{Ieee80211AuthFrameOpenSystem, WLAN_AUTH_OPEN};
use super::pasn::{Ieee80211AuthFramePasn, WLAN_AUTH_PASN};
use super::sae::{Ieee80211AuthFrameSae, WLAN_AUTH_SAE};
use super::shared_key::{Ieee80211AuthFrameSharedKey, WLAN_AUTH_SHARED_KEY};
use super::vendor_specific::{
    Ieee80211AuthFrameVendorSpecific, WLAN_AUTH_VENDOR_SPECIFIC,
};

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

impl From<Ieee80211AuthAlgorithm> for u16 {
    fn from(algorithm: Ieee80211AuthAlgorithm) -> Self {
        match algorithm {
            Ieee80211AuthAlgorithm::OpenSystem => WLAN_AUTH_OPEN,
            Ieee80211AuthAlgorithm::SharedKey => WLAN_AUTH_SHARED_KEY,
            Ieee80211AuthAlgorithm::FastBssTransition => WLAN_AUTH_FT,
            Ieee80211AuthAlgorithm::Sae => WLAN_AUTH_SAE,
            Ieee80211AuthAlgorithm::FilsSharedKey => WLAN_AUTH_FILS_SK,
            Ieee80211AuthAlgorithm::FilsSharedKeyPfs => WLAN_AUTH_FILS_SK_PFS,
            Ieee80211AuthAlgorithm::FilsPublicKey => WLAN_AUTH_FILS_PK,
            Ieee80211AuthAlgorithm::Pasn => WLAN_AUTH_PASN,
            Ieee80211AuthAlgorithm::Ieee8021x => WLAN_AUTH_IEEE8021X,
            Ieee80211AuthAlgorithm::Eppke => WLAN_AUTH_EPPKE,
            Ieee80211AuthAlgorithm::Leap => WLAN_AUTH_LEAP,
            Ieee80211AuthAlgorithm::VendorSpecific => WLAN_AUTH_VENDOR_SPECIFIC,
            Ieee80211AuthAlgorithm::Other(algorithm) => algorithm,
        }
    }
}

/// A parsed IEEE 802.11 Authentication management frame, as delivered in the
/// `NL80211_ATTR_FRAME` of an `NL80211_CMD_AUTHENTICATE` event
/// (IEEE Std 802.11-2024 §9.3.3.11, Table 9-70).
///
/// Each algorithm-specific variant models the 24-byte MAC header
/// (DA/SA/BSSID/sequence, see §9.2.4.3 and §9.2.4.4) together with the
/// Authentication algorithm number, transaction sequence number and status
/// code.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum Ieee80211AuthFrame {
    /// Open System authentication (algorithm 0).
    OpenSystem(Ieee80211AuthFrameOpenSystem),
    /// Shared Key authentication (algorithm 1).
    SharedKey(Ieee80211AuthFrameSharedKey),
    /// Fast BSS Transition authentication (algorithm 2).
    FastBssTransition(Ieee80211AuthFrameFastBssTransition),
    /// Simultaneous Authentication of Equals (algorithm 3).
    Sae(Ieee80211AuthFrameSae),
    /// FILS Shared Key authentication without PFS (algorithm 4).
    FilsSharedKey(Ieee80211AuthFrameFilsSharedKey),
    /// FILS Shared Key authentication with PFS (algorithm 5).
    FilsSharedKeyPfs(Ieee80211AuthFrameFilsSharedKeyPfs),
    /// FILS Public Key authentication (algorithm 6).
    FilsPublicKey(Ieee80211AuthFrameFilsPublicKey),
    /// PASN authentication (algorithm 7).
    Pasn(Ieee80211AuthFramePasn),
    /// IEEE 802.1X authentication (algorithm 8).
    Ieee8021x(Ieee80211AuthFrameIeee8021x),
    /// EPPKE authentication (algorithm 9).
    Eppke(Ieee80211AuthFrameEppke),
    /// LEAP authentication (algorithm 128).
    Leap(Ieee80211AuthFrameLeap),
    /// Vendor specific authentication (algorithm 65 535).
    VendorSpecific(Ieee80211AuthFrameVendorSpecific),
    /// Any other, unmodelled authentication algorithm.
    Other(Ieee80211AuthFrameOther),
}

/// A parsed Authentication frame with an algorithm that is not modelled by
/// [`Ieee80211AuthFrame`]. The raw algorithm number is preserved in
/// [`algorithm`](Self::algorithm).
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct Ieee80211AuthFrameOther {
    /// Authentication algorithm.
    pub algorithm: Ieee80211AuthAlgorithm,
    /// Frame Control.
    pub frame_control: u16,
    /// Duration.
    pub duration: u16,
    /// Address 1 (DA).
    pub da: [u8; 6],
    /// Address 2 (SA).
    pub sa: [u8; 6],
    /// Address 3 (BSSID).
    pub bssid: [u8; 6],
    /// Sequence Control.
    pub seq_ctrl: u16,
    /// Authentication transaction sequence number.
    pub transaction: u16,
    /// IEEE 802.11 status code.
    pub status_code: Ieee80211StatusCode,
    /// Remaining frame body after the fixed fields.
    payload: Vec<u8>,
}

impl Ieee80211AuthFrameOther {
    /// Parse a full IEEE 802.11 Authentication management frame with an
    /// unmodelled algorithm.
    pub fn parse(data: &[u8]) -> Result<Self, DecodeError> {
        let (fixed, payload) = parse_auth_frame(data, None)?;
        Ok(Self {
            algorithm: Ieee80211AuthAlgorithm::from(fixed.auth_alg),
            frame_control: fixed.frame_control,
            duration: fixed.duration,
            da: fixed.da,
            sa: fixed.sa,
            bssid: fixed.bssid,
            seq_ctrl: fixed.seq_ctrl,
            transaction: fixed.transaction,
            status_code: fixed.status_code,
            payload: payload.to_vec(),
        })
    }

    /// The STA MAC address in an infrastructure BSS.
    pub fn sta_mac(&self) -> [u8; 6] {
        if self.da == self.bssid {
            self.sa
        } else {
            self.da
        }
    }

    /// Remaining frame body after the fixed fields.
    pub fn body(&self) -> &[u8] {
        &self.payload
    }

    /// Serialize this frame into raw 802.11 management frame bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = vec![0u8; self.buffer_len()];
        self.emit(&mut buffer);
        buffer
    }

    fn fixed(&self) -> Ieee80211AuthFrameFixed {
        Ieee80211AuthFrameFixed {
            frame_control: self.frame_control,
            duration: self.duration,
            da: self.da,
            sa: self.sa,
            bssid: self.bssid,
            seq_ctrl: self.seq_ctrl,
            auth_alg: u16::from(self.algorithm),
            transaction: self.transaction,
            status_code: self.status_code,
        }
    }
}

impl Emitable for Ieee80211AuthFrameOther {
    fn buffer_len(&self) -> usize {
        auth_frame_buffer_len(self.payload.len())
    }

    fn emit(&self, buffer: &mut [u8]) {
        emit_auth_frame(&self.fixed(), &self.payload, buffer);
    }
}

impl Ieee80211AuthFrame {
    /// Minimum length of an Authentication management frame: 24-byte MAC
    /// header + algorithm(2) + transaction(2) + status(2).
    const MIN_FRAME_LEN: usize = 30;
    /// Parse an Authentication management frame from its raw bytes.
    ///
    /// Returns an error when the frame is shorter than
    /// [`MIN_FRAME_LEN`](Self::MIN_FRAME_LEN) bytes.
    pub fn parse(data: &[u8]) -> Result<Self, DecodeError> {
        if data.len() < Self::MIN_FRAME_LEN {
            return Err(DecodeError::from(format!(
                "authentication frame too short: {} bytes",
                data.len()
            )));
        }

        let algorithm = Ieee80211AuthAlgorithm::from(u16::from_le_bytes([
            data[24], data[25],
        ]));

        Ok(match algorithm {
            Ieee80211AuthAlgorithm::OpenSystem => {
                Self::OpenSystem(Ieee80211AuthFrameOpenSystem::parse(data)?)
            }
            Ieee80211AuthAlgorithm::SharedKey => {
                Self::SharedKey(Ieee80211AuthFrameSharedKey::parse(data)?)
            }
            Ieee80211AuthAlgorithm::FastBssTransition => {
                Self::FastBssTransition(
                    Ieee80211AuthFrameFastBssTransition::parse(data)?,
                )
            }
            Ieee80211AuthAlgorithm::Sae => {
                Self::Sae(Ieee80211AuthFrameSae::parse(data)?)
            }
            Ieee80211AuthAlgorithm::FilsSharedKey => Self::FilsSharedKey(
                Ieee80211AuthFrameFilsSharedKey::parse(data)?,
            ),
            Ieee80211AuthAlgorithm::FilsSharedKeyPfs => Self::FilsSharedKeyPfs(
                Ieee80211AuthFrameFilsSharedKeyPfs::parse(data)?,
            ),
            Ieee80211AuthAlgorithm::FilsPublicKey => Self::FilsPublicKey(
                Ieee80211AuthFrameFilsPublicKey::parse(data)?,
            ),
            Ieee80211AuthAlgorithm::Pasn => {
                Self::Pasn(Ieee80211AuthFramePasn::parse(data)?)
            }
            Ieee80211AuthAlgorithm::Ieee8021x => {
                Self::Ieee8021x(Ieee80211AuthFrameIeee8021x::parse(data)?)
            }
            Ieee80211AuthAlgorithm::Eppke => {
                Self::Eppke(Ieee80211AuthFrameEppke::parse(data)?)
            }
            Ieee80211AuthAlgorithm::Leap => {
                Self::Leap(Ieee80211AuthFrameLeap::parse(data)?)
            }
            Ieee80211AuthAlgorithm::VendorSpecific => Self::VendorSpecific(
                Ieee80211AuthFrameVendorSpecific::parse(data)?,
            ),
            Ieee80211AuthAlgorithm::Other(_) => {
                Self::Other(Ieee80211AuthFrameOther::parse(data)?)
            }
        })
    }

    /// The authentication algorithm of this frame.
    pub fn algorithm(&self) -> Ieee80211AuthAlgorithm {
        match self {
            Self::OpenSystem(_) => Ieee80211AuthAlgorithm::OpenSystem,
            Self::SharedKey(_) => Ieee80211AuthAlgorithm::SharedKey,
            Self::FastBssTransition(_) => {
                Ieee80211AuthAlgorithm::FastBssTransition
            }
            Self::Sae(_) => Ieee80211AuthAlgorithm::Sae,
            Self::FilsSharedKey(_) => Ieee80211AuthAlgorithm::FilsSharedKey,
            Self::FilsSharedKeyPfs(_) => {
                Ieee80211AuthAlgorithm::FilsSharedKeyPfs
            }
            Self::FilsPublicKey(_) => Ieee80211AuthAlgorithm::FilsPublicKey,
            Self::Pasn(_) => Ieee80211AuthAlgorithm::Pasn,
            Self::Ieee8021x(_) => Ieee80211AuthAlgorithm::Ieee8021x,
            Self::Eppke(_) => Ieee80211AuthAlgorithm::Eppke,
            Self::Leap(_) => Ieee80211AuthAlgorithm::Leap,
            Self::VendorSpecific(_) => Ieee80211AuthAlgorithm::VendorSpecific,
            Self::Other(frame) => frame.algorithm,
        }
    }

    /// Authentication transaction sequence number.
    pub fn transaction(&self) -> u16 {
        match self {
            Self::OpenSystem(frame) => frame.transaction,
            Self::SharedKey(frame) => frame.transaction,
            Self::FastBssTransition(frame) => frame.transaction,
            Self::Sae(frame) => frame.transaction,
            Self::FilsSharedKey(frame) => frame.transaction,
            Self::FilsSharedKeyPfs(frame) => frame.transaction,
            Self::FilsPublicKey(frame) => frame.transaction,
            Self::Pasn(frame) => frame.transaction,
            Self::Ieee8021x(frame) => frame.transaction,
            Self::Eppke(frame) => frame.transaction,
            Self::Leap(frame) => frame.transaction,
            Self::VendorSpecific(frame) => frame.transaction,
            Self::Other(frame) => frame.transaction,
        }
    }

    /// IEEE 802.11 status code.
    pub fn status_code(&self) -> Ieee80211StatusCode {
        match self {
            Self::OpenSystem(frame) => frame.status_code,
            Self::SharedKey(frame) => frame.status_code,
            Self::FastBssTransition(frame) => frame.status_code,
            Self::Sae(frame) => frame.status_code,
            Self::FilsSharedKey(frame) => frame.status_code,
            Self::FilsSharedKeyPfs(frame) => frame.status_code,
            Self::FilsPublicKey(frame) => frame.status_code,
            Self::Pasn(frame) => frame.status_code,
            Self::Ieee8021x(frame) => frame.status_code,
            Self::Eppke(frame) => frame.status_code,
            Self::Leap(frame) => frame.status_code,
            Self::VendorSpecific(frame) => frame.status_code,
            Self::Other(frame) => frame.status_code,
        }
    }

    /// Frame body after the fixed authentication fields, kept as raw bytes
    /// for the algorithm-specific parsing.
    pub fn body(&self) -> &[u8] {
        match self {
            Self::OpenSystem(frame) => frame.body(),
            Self::SharedKey(frame) => frame.body(),
            Self::FastBssTransition(frame) => frame.body(),
            Self::Sae(frame) => frame.body(),
            Self::FilsSharedKey(frame) => frame.body(),
            Self::FilsSharedKeyPfs(frame) => frame.body(),
            Self::FilsPublicKey(frame) => frame.body(),
            Self::Pasn(frame) => frame.body(),
            Self::Ieee8021x(frame) => frame.body(),
            Self::Eppke(frame) => frame.body(),
            Self::Leap(frame) => frame.body(),
            Self::VendorSpecific(frame) => frame.body(),
            Self::Other(frame) => frame.body(),
        }
    }

    /// Whether this is a Simultaneous Authentication of Equals (SAE) frame.
    pub fn is_sae(&self) -> bool {
        matches!(self, Self::Sae(_))
    }

    /// The typed SAE frame, when this frame uses authentication algorithm 3.
    pub fn sae(&self) -> Option<&Ieee80211AuthFrameSae> {
        match self {
            Self::Sae(frame) => Some(frame),
            _ => None,
        }
    }

    /// Parse an SAE Authentication frame from a full 802.11 mgmt frame.
    ///
    /// Returns `None` when the frame control does not describe a management
    /// Authentication frame, when the authentication algorithm is not SAE,
    /// or when the frame is too short.
    pub fn parse_sae(full_frame: &[u8]) -> Option<Ieee80211AuthFrameSae> {
        Ieee80211AuthFrameSae::parse(full_frame).ok()
    }
}
