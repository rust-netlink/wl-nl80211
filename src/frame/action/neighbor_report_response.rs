// SPDX-License-Identifier: MIT

use netlink_packet_core::{DecodeError, Emitable};

use crate::mac::ETH_ALEN;

use super::buffer::{
    action_frame_buffer_len, emit_action_frame, parse_action_frame,
    Ieee80211ActionFrameFixed,
};

/// Neighbor Report element ID.
const IE_ID_NEIGHBOR_REPORT: u8 = 52;

/// One Neighbor Report element (802.11k): BSSID + BSSID Information +
/// Operating Class + Channel Number + PHY type, followed by optional
/// subelements. This is the format hostapd and iwd use (the minimum
/// element payload is 13 octets).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Ieee80211NeighborReportEntry {
    pub bssid: [u8; ETH_ALEN],
    pub bssid_info: u32,
    pub operating_class: u8,
    pub channel: u8,
    pub phy_type: u8,
}

/// A parsed Neighbor Report Response.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Ieee80211NeighborReportResponse {
    pub dialog_token: u8,
    pub entries: Vec<Ieee80211NeighborReportEntry>,
}

impl Ieee80211NeighborReportResponse {
    /// Radio Measurement action category (802.11-2016 Table 9-42).
    pub const CATEGORY: u8 = 5;
    /// Radio Measurement action: Neighbor Report Response.
    pub const ACTION: u8 = 5;

    /// Parse a Neighbor Report Response from the Action body (after the
    /// category and action octets): dialog token followed by Neighbor
    /// Report elements.
    pub fn parse(body: &[u8]) -> Option<Self> {
        let dialog_token = *body.first()?;
        let mut entries = Vec::new();
        let mut pos = 1;
        while pos + 2 <= body.len() {
            let id = body[pos];
            let len = body[pos + 1] as usize;
            let start = pos + 2;
            if start + len > body.len() {
                break;
            }
            let elem = &body[start..start + len];
            if id == IE_ID_NEIGHBOR_REPORT && elem.len() >= 13 {
                entries.push(Ieee80211NeighborReportEntry {
                    bssid: elem[0..6].try_into().unwrap(),
                    bssid_info: u32::from_le_bytes([
                        elem[6], elem[7], elem[8], elem[9],
                    ]),
                    operating_class: elem[10],
                    channel: elem[11],
                    phy_type: elem[12],
                });
            }
            pos = start + len;
        }
        Some(Self {
            dialog_token,
            entries,
        })
    }
}

/// A full IEEE 802.11 Radio Measurement Neighbor Report Response Action
/// frame.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct Ieee80211ActionFrameNeighborReportResponse {
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
    /// Parsed Neighbor Report Response body.
    pub response: Ieee80211NeighborReportResponse,
    /// Raw Action body after the category and action octets.
    body: Vec<u8>,
}

impl Ieee80211ActionFrameNeighborReportResponse {
    /// Parse a full Neighbor Report Response Action frame.
    pub fn parse(data: &[u8]) -> Result<Self, DecodeError> {
        let (fixed, body) = parse_action_frame(data)?;
        if fixed.category != Ieee80211NeighborReportResponse::CATEGORY
            || fixed.action != Ieee80211NeighborReportResponse::ACTION
        {
            return Err(DecodeError::from(
                "not a Neighbor Report Response Action frame",
            ));
        }
        let response = Ieee80211NeighborReportResponse::parse(body).ok_or(
            DecodeError::from("Neighbor Report Response body too short"),
        )?;
        Ok(Self::from_fixed(fixed, body.to_vec(), response))
    }

    pub(crate) fn from_fixed(
        fixed: Ieee80211ActionFrameFixed,
        body: Vec<u8>,
        response: Ieee80211NeighborReportResponse,
    ) -> Self {
        Self {
            frame_control: fixed.frame_control,
            duration: fixed.duration,
            da: fixed.da,
            sa: fixed.sa,
            bssid: fixed.bssid,
            seq_ctrl: fixed.seq_ctrl,
            response,
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
            category: Ieee80211NeighborReportResponse::CATEGORY,
            action: Ieee80211NeighborReportResponse::ACTION,
        }
    }
}

impl Emitable for Ieee80211ActionFrameNeighborReportResponse {
    fn buffer_len(&self) -> usize {
        action_frame_buffer_len(self.body.len())
    }

    fn emit(&self, buffer: &mut [u8]) {
        emit_action_frame(&self.fixed(), &self.body, buffer);
    }
}
