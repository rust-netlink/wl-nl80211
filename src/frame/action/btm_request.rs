// SPDX-License-Identifier: MIT

use netlink_packet_core::{DecodeError, Emitable};

use crate::mac::ETH_ALEN;

use super::buffer::{
    action_frame_buffer_len, emit_action_frame, parse_action_frame,
    Ieee80211ActionFrameFixed,
};

/// Request Mode bits (802.11-2020 Table 9-459).
const REQ_MODE_PREF_CAND_LIST: u8 = 1 << 0;
const REQ_MODE_BSS_TERMINATION: u8 = 1 << 3;
const REQ_MODE_ESS_DISASSOC_IMMINENT: u8 = 1 << 4;

/// Neighbor Report element ID carrying BTM candidate entries
/// (802.11-2020 §9.4.2.21).
const IE_ID_NEIGHBOR_REPORT: u8 = 52;

/// One BSS Transition Management candidate: the fields of its Neighbor
/// Report element body.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Ieee80211BtmCandidate {
    pub bssid: [u8; ETH_ALEN],
    pub bssid_info: u32,
    pub operating_class: u8,
    pub channel: u8,
    pub phy_type: u8,
    /// Preference octet (present when the request carries a preferred
    /// candidate list; higher = preferred).
    pub preference: Option<u8>,
}

/// A parsed BSS Transition Management Request.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Ieee80211BtmRequest {
    pub dialog_token: u8,
    pub preferred_candidates: bool,
    pub disassoc_timer: u16,
    pub validity_interval: u8,
    pub candidates: Vec<Ieee80211BtmCandidate>,
}

impl Ieee80211BtmRequest {
    /// WNM action category (802.11-2020 Table 9-46).
    pub const CATEGORY: u8 = 10;
    /// BSS Transition Management Request action (802.11-2020 Table 9-459;
    /// note: action 6 is the BTM *Query*).
    pub const ACTION: u8 = 7;

    /// Parse a BTM Request from the action frame body (after the category
    /// and action octets).
    pub fn parse(body: &[u8]) -> Option<Self> {
        if body.len() < 5 {
            return None;
        }
        let dialog_token = body[0];
        let req_mode = body[1];
        let disassoc_timer = u16::from_le_bytes([body[2], body[3]]);
        let validity_interval = body[4];
        let mut pos = 5;

        if req_mode & REQ_MODE_BSS_TERMINATION != 0 {
            // Subelement: ID(1) + length(1) + 10 octets of data.
            pos += 12;
        }
        if req_mode & REQ_MODE_ESS_DISASSOC_IMMINENT != 0 {
            if body.len() < pos + 1 {
                return None;
            }
            let url_len = body[pos] as usize;
            pos += 1 + url_len;
        }

        let mut candidates = Vec::new();
        while pos + 2 <= body.len() {
            let id = body[pos];
            let len = body[pos + 1] as usize;
            let start = pos + 2;
            if start + len > body.len() {
                break;
            }
            let elem = &body[start..start + len];
            if id == IE_ID_NEIGHBOR_REPORT && elem.len() >= 13 {
                candidates.push(Ieee80211BtmCandidate {
                    bssid: elem[0..6].try_into().unwrap(),
                    bssid_info: u32::from_le_bytes([
                        elem[6], elem[7], elem[8], elem[9],
                    ]),
                    operating_class: elem[10],
                    channel: elem[11],
                    phy_type: elem[12],
                    // The preference octet trails the mandatory part when
                    // the AP sends preferred candidates.
                    preference: elem.get(13).copied(),
                });
            }
            pos = start + len;
        }

        Some(Self {
            dialog_token,
            preferred_candidates: req_mode & REQ_MODE_PREF_CAND_LIST != 0,
            disassoc_timer,
            validity_interval,
            candidates,
        })
    }
}

/// A full IEEE 802.11 WNM BSS Transition Management Request Action frame.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct Ieee80211ActionFrameBtmRequest {
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
    /// Parsed BTM Request body.
    pub request: Ieee80211BtmRequest,
    /// Raw Action body after the category and action octets.
    body: Vec<u8>,
}

impl Ieee80211ActionFrameBtmRequest {
    /// Parse a full BTM Request Action frame.
    pub fn parse(data: &[u8]) -> Result<Self, DecodeError> {
        let (fixed, body) = parse_action_frame(data)?;
        if fixed.category != Ieee80211BtmRequest::CATEGORY
            || fixed.action != Ieee80211BtmRequest::ACTION
        {
            return Err(DecodeError::from(
                "not a BSS Transition Management Request Action frame",
            ));
        }
        let request = Ieee80211BtmRequest::parse(body)
            .ok_or(DecodeError::from("BTM Request body too short"))?;
        Ok(Self::from_fixed(fixed, body.to_vec(), request))
    }

    pub(crate) fn from_fixed(
        fixed: Ieee80211ActionFrameFixed,
        body: Vec<u8>,
        request: Ieee80211BtmRequest,
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
            category: Ieee80211BtmRequest::CATEGORY,
            action: Ieee80211BtmRequest::ACTION,
        }
    }
}

impl Emitable for Ieee80211ActionFrameBtmRequest {
    fn buffer_len(&self) -> usize {
        action_frame_buffer_len(self.body.len())
    }

    fn emit(&self, buffer: &mut [u8]) {
        emit_action_frame(&self.fixed(), &self.body, buffer);
    }
}
