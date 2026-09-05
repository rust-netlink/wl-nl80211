// SPDX-License-Identifier: MIT

use netlink_packet_core::{DecodeError, Emitable};

use super::buffer::{
    action_frame_buffer_len, emit_action_frame, parse_action_frame,
    Ieee80211ActionFrameFixed,
};

/// A Neighbor Report Request action frame body (category, action, and
/// dialog token). iwd sends just the dialog token; a non-zero token is
/// required.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Ieee80211NeighborReportRequest {
    /// Dialog token echoed by the Neighbor Report Response.
    pub dialog_token: u8,
}

impl Ieee80211NeighborReportRequest {
    /// Radio Measurement action category (802.11-2016 Table 9-42).
    pub const CATEGORY: u8 = 5;
    /// Radio Measurement action: Neighbor Report Request.
    pub const ACTION: u8 = 4;

    pub fn new(dialog_token: u8) -> Self {
        Self { dialog_token }
    }

    /// Parse the Action body after the category and action octets.
    pub fn parse(body: &[u8]) -> Option<Self> {
        Some(Self {
            dialog_token: *body.first()?,
        })
    }

    /// Build the action frame body (category, action, and dialog token).
    pub fn build(&self) -> Vec<u8> {
        vec![Self::CATEGORY, Self::ACTION, self.dialog_token]
    }
}

/// A full IEEE 802.11 Radio Measurement Neighbor Report Request Action
/// frame.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct Ieee80211ActionFrameNeighborReportRequest {
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
    /// Parsed Neighbor Report Request body.
    pub request: Ieee80211NeighborReportRequest,
    /// Raw Action body after the category and action octets.
    body: Vec<u8>,
}

impl Ieee80211ActionFrameNeighborReportRequest {
    /// Create a STA-to-AP Neighbor Report Request Action frame.
    pub fn new(
        sta_mac: [u8; 6],
        bssid: [u8; 6],
        request: Ieee80211NeighborReportRequest,
    ) -> Self {
        Self::from_fixed(
            Ieee80211ActionFrameFixed {
                frame_control: 0x00D0,
                duration: 0,
                da: bssid,
                sa: sta_mac,
                bssid,
                seq_ctrl: 0,
                category: Ieee80211NeighborReportRequest::CATEGORY,
                action: Ieee80211NeighborReportRequest::ACTION,
            },
            vec![request.dialog_token],
            request,
        )
    }

    /// Parse a full Neighbor Report Request Action frame.
    pub fn parse(data: &[u8]) -> Result<Self, DecodeError> {
        let (fixed, body) = parse_action_frame(data)?;
        if fixed.category != Ieee80211NeighborReportRequest::CATEGORY
            || fixed.action != Ieee80211NeighborReportRequest::ACTION
        {
            return Err(DecodeError::from(
                "not a Neighbor Report Request Action frame",
            ));
        }
        let request = Ieee80211NeighborReportRequest::parse(body).ok_or(
            DecodeError::from("Neighbor Report Request body too short"),
        )?;
        Ok(Self::from_fixed(fixed, body.to_vec(), request))
    }

    pub(crate) fn from_fixed(
        fixed: Ieee80211ActionFrameFixed,
        body: Vec<u8>,
        request: Ieee80211NeighborReportRequest,
    ) -> Self {
        Self {
            frame_control: fixed.frame_control,
            duration: fixed.duration,
            da: fixed.da,
            sa: fixed.sa,
            bssid: fixed.bssid,
            seq_ctrl: fixed.seq_ctrl,
            request,
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

    /// The raw Action body after the category and action octets.
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
            category: Ieee80211NeighborReportRequest::CATEGORY,
            action: Ieee80211NeighborReportRequest::ACTION,
        }
    }
}

impl Emitable for Ieee80211ActionFrameNeighborReportRequest {
    fn buffer_len(&self) -> usize {
        action_frame_buffer_len(self.body.len())
    }

    fn emit(&self, buffer: &mut [u8]) {
        emit_action_frame(&self.fixed(), &self.body, buffer);
    }
}
