// SPDX-License-Identifier: MIT

//! Radio Resource Measurement (RRM, 802.11k) action frames: the
//! Neighbor Report Request / Response used to narrow a signal-triggered
//! roam scan to the channels the connected AP considers part of the ESS.
//!
//! Action numbers follow 802.11-2016 Table 9-43: 4 is the Neighbor
//! Report Request, 5 the Neighbor Report Response (iwd uses the same
//! numbers in `src/netdev.c`).

use crate::mac::ETH_ALEN;

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

/// A Neighbor Report Request action frame (category, action, and dialog
/// token). iwd sends just the dialog token; a non-zero token is required.
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

    /// Build the action frame body (category, action, and dialog token).
    pub fn build(&self) -> Vec<u8> {
        vec![Self::CATEGORY, Self::ACTION, self.dialog_token]
    }
}

impl Ieee80211NeighborReportResponse {
    /// Radio Measurement action category (802.11-2016 Table 9-42).
    pub const CATEGORY: u8 = 5;
    /// Radio Measurement action: Neighbor Report Response.
    pub const ACTION: u8 = 5;

    /// Parse a Neighbor Report Response from the action frame body (after
    /// the category and action octets): dialog token followed by Neighbor
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
