// SPDX-License-Identifier: MIT

use netlink_packet_core::{DecodeError, Emitable};

use super::buffer::{
    action_frame_buffer_len, emit_action_frame, parse_action_frame,
    Ieee80211ActionFrameFixed,
};

/// A parsed Action frame whose category/action is not modelled by
/// [`super::Ieee80211ActionFrame`], or whose typed body is malformed.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct Ieee80211ActionFrameOther {
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
    /// Action category octet.
    pub category: u8,
    /// Action code within the category.
    pub action: u8,
    /// Remaining Action body after the category and action octets.
    body: Vec<u8>,
}

impl Ieee80211ActionFrameOther {
    /// Create an unmodelled Action frame in the STA-to-AP direction.
    pub fn new(
        sta_mac: [u8; 6],
        bssid: [u8; 6],
        category: u8,
        action: u8,
        body: Vec<u8>,
    ) -> Self {
        Self::from_fixed(
            Ieee80211ActionFrameFixed {
                frame_control: 0x00D0,
                duration: 0,
                da: bssid,
                sa: sta_mac,
                bssid,
                seq_ctrl: 0,
                category,
                action,
            },
            body,
        )
    }

    /// Parse a full IEEE 802.11 Action management frame with an unmodelled
    /// category/action.
    pub fn parse(data: &[u8]) -> Result<Self, DecodeError> {
        let (fixed, body) = parse_action_frame(data)?;
        Ok(Self::from_fixed(fixed, body.to_vec()))
    }

    pub(crate) fn from_fixed(
        fixed: Ieee80211ActionFrameFixed,
        body: Vec<u8>,
    ) -> Self {
        Self {
            frame_control: fixed.frame_control,
            duration: fixed.duration,
            da: fixed.da,
            sa: fixed.sa,
            bssid: fixed.bssid,
            seq_ctrl: fixed.seq_ctrl,
            category: fixed.category,
            action: fixed.action,
            body,
        }
    }

    /// The STA MAC address in an infrastructure BSS.
    pub fn sta_mac(&self) -> [u8; 6] {
        if self.da == self.bssid {
            self.sa
        } else {
            self.da
        }
    }

    /// The Action body after the category and action octets.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Serialize this frame into raw 802.11 management frame bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = vec![0u8; self.buffer_len()];
        self.emit(&mut buffer);
        buffer
    }

    fn fixed(&self) -> Ieee80211ActionFrameFixed {
        Ieee80211ActionFrameFixed {
            frame_control: self.frame_control,
            duration: self.duration,
            da: self.da,
            sa: self.sa,
            bssid: self.bssid,
            seq_ctrl: self.seq_ctrl,
            category: self.category,
            action: self.action,
        }
    }
}

impl Emitable for Ieee80211ActionFrameOther {
    fn buffer_len(&self) -> usize {
        action_frame_buffer_len(self.body.len())
    }

    fn emit(&self, buffer: &mut [u8]) {
        emit_action_frame(&self.fixed(), &self.body, buffer);
    }
}
