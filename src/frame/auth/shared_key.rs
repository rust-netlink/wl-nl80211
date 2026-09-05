// SPDX-License-Identifier: MIT

use netlink_packet_core::{DecodeError, Emitable};

use crate::Ieee80211StatusCode;

use super::buffer::{
    auth_frame_buffer_len, emit_auth_frame, parse_auth_frame,
    Ieee80211AuthFrameFixed,
};

/// `WLAN_AUTH_SHARED_KEY` (1): Shared Key authentication.
pub(crate) const WLAN_AUTH_SHARED_KEY: u16 = 1;

/// A parsed or buildable IEEE 802.11 Shared Key Authentication management
/// frame (legacy algorithm 1). The challenge text is kept in the raw frame
/// body.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct Ieee80211AuthFrameSharedKey {
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

impl Ieee80211AuthFrameSharedKey {
    /// Create a Shared Key Authentication frame in the STA-to-AP direction.
    pub fn new(
        sta_mac: [u8; 6],
        bssid: [u8; 6],
        transaction: u16,
        status_code: Ieee80211StatusCode,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            frame_control: 0x00B0,
            duration: 0,
            da: bssid,
            sa: sta_mac,
            bssid,
            seq_ctrl: 0,
            transaction,
            status_code,
            payload,
        }
    }

    /// Parse a full IEEE 802.11 Shared Key Authentication management frame.
    pub fn parse(data: &[u8]) -> Result<Self, DecodeError> {
        let (fixed, payload) =
            parse_auth_frame(data, Some(WLAN_AUTH_SHARED_KEY))?;
        Ok(Self::from_fixed(fixed, payload.to_vec()))
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

    fn from_fixed(fixed: Ieee80211AuthFrameFixed, payload: Vec<u8>) -> Self {
        Self {
            frame_control: fixed.frame_control,
            duration: fixed.duration,
            da: fixed.da,
            sa: fixed.sa,
            bssid: fixed.bssid,
            seq_ctrl: fixed.seq_ctrl,
            transaction: fixed.transaction,
            status_code: fixed.status_code,
            payload,
        }
    }

    fn fixed(&self) -> Ieee80211AuthFrameFixed {
        Ieee80211AuthFrameFixed {
            frame_control: self.frame_control,
            duration: self.duration,
            da: self.da,
            sa: self.sa,
            bssid: self.bssid,
            seq_ctrl: self.seq_ctrl,
            auth_alg: WLAN_AUTH_SHARED_KEY,
            transaction: self.transaction,
            status_code: self.status_code,
        }
    }
}

impl Emitable for Ieee80211AuthFrameSharedKey {
    fn buffer_len(&self) -> usize {
        auth_frame_buffer_len(self.payload.len())
    }

    fn emit(&self, buffer: &mut [u8]) {
        emit_auth_frame(&self.fixed(), &self.payload, buffer);
    }
}
