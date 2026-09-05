// SPDX-License-Identifier: MIT

use netlink_packet_core::{DecodeError, Emitable};

use crate::mac::ETH_ALEN;

use super::buffer::{
    action_frame_buffer_len, emit_action_frame, parse_action_frame,
    Ieee80211ActionFrameFixed,
};

/// A BSS Transition Management Response action frame body (category +
/// action + body): Dialog Token (1) || Status Code (1) || BSS Termination
/// Delay (1) || Target BSSID (6). The target BSSID is the accepted
/// candidate; zero bytes reject without naming a BSS.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Ieee80211BtmResponse {
    /// Dialog token echoed from the BTM Request.
    pub dialog_token: u8,
    /// Response status code, one of the [`BTM_STATUS_*`] constants.
    pub status: u8,
    /// The accepted candidate BSSID, or zero bytes when rejecting.
    pub target_bssid: [u8; ETH_ALEN],
}

impl Ieee80211BtmResponse {
    /// WNM action category (802.11-2020 Table 9-46).
    pub const CATEGORY: u8 = 10;
    /// BSS Transition Management Response action (802.11-2020 Table 9-459).
    pub const ACTION: u8 = 8;
    /// BTM Response status: accept (802.11-2020 Table 9-461).
    pub const STATUS_ACCEPT: u8 = 0;
    /// BTM Response status: reject, unspecified reason (802.11-2020 Table
    /// 9-461).
    pub const STATUS_REJECT_UNSPECIFIED: u8 = 1;

    pub fn new(
        dialog_token: u8,
        status: u8,
        target_bssid: [u8; ETH_ALEN],
    ) -> Self {
        Self {
            dialog_token,
            status,
            target_bssid,
        }
    }

    /// Parse the Action body after the category and action octets.
    pub fn parse(body: &[u8]) -> Option<Self> {
        if body.len() < 9 {
            return None;
        }
        Some(Self {
            dialog_token: body[0],
            status: body[1],
            target_bssid: body[3..9].try_into().unwrap(),
        })
    }

    /// Build the action frame body (category + action + body).
    pub fn build(&self) -> Vec<u8> {
        let mut frame = Vec::with_capacity(2 + 9);
        frame.push(Self::CATEGORY);
        frame.push(Self::ACTION);
        frame.push(self.dialog_token);
        frame.push(self.status);
        frame.push(0); // BSS Termination Delay (unused)
        frame.extend_from_slice(&self.target_bssid);
        frame
    }
}

/// A full IEEE 802.11 WNM BSS Transition Management Response Action frame.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct Ieee80211ActionFrameBtmResponse {
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
    /// Parsed/buildable BTM Response body.
    pub response: Ieee80211BtmResponse,
    /// Raw Action body after the category and action octets.
    body: Vec<u8>,
}

impl Ieee80211ActionFrameBtmResponse {
    /// Create a STA-to-AP BTM Response Action frame.
    pub fn new(
        sta_mac: [u8; 6],
        bssid: [u8; 6],
        response: Ieee80211BtmResponse,
    ) -> Self {
        let body = response.build().split_off(2);
        Self::from_fixed(
            Ieee80211ActionFrameFixed {
                frame_control: 0x00D0,
                duration: 0,
                da: bssid,
                sa: sta_mac,
                bssid,
                seq_ctrl: 0,
                category: Ieee80211BtmResponse::CATEGORY,
                action: Ieee80211BtmResponse::ACTION,
            },
            body,
            response,
        )
    }

    /// Parse a full BTM Response Action frame.
    pub fn parse(data: &[u8]) -> Result<Self, DecodeError> {
        let (fixed, body) = parse_action_frame(data)?;
        if fixed.category != Ieee80211BtmResponse::CATEGORY
            || fixed.action != Ieee80211BtmResponse::ACTION
        {
            return Err(DecodeError::from(
                "not a BSS Transition Management Response Action frame",
            ));
        }
        let response = Ieee80211BtmResponse::parse(body)
            .ok_or(DecodeError::from("BTM Response body too short"))?;
        Ok(Self::from_fixed(fixed, body.to_vec(), response))
    }

    pub(crate) fn from_fixed(
        fixed: Ieee80211ActionFrameFixed,
        body: Vec<u8>,
        response: Ieee80211BtmResponse,
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
            category: Ieee80211BtmResponse::CATEGORY,
            action: Ieee80211BtmResponse::ACTION,
        }
    }
}

impl Emitable for Ieee80211ActionFrameBtmResponse {
    fn buffer_len(&self) -> usize {
        action_frame_buffer_len(self.body.len())
    }

    fn emit(&self, buffer: &mut [u8]) {
        emit_action_frame(&self.fixed(), &self.body, buffer);
    }
}
