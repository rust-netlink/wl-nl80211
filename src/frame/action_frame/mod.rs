// SPDX-License-Identifier: MIT

//! IEEE 802.11 Action management frame parsing types.

mod btm_request;
mod btm_response;
mod buffer;
mod neighbor_report_request;
mod neighbor_report_response;
mod other;

use netlink_packet_core::DecodeError;

use self::buffer::parse_action_frame;

pub use self::btm_request::{
    Ieee80211ActionFrameBtmRequest, Ieee80211BtmCandidate, Ieee80211BtmRequest,
};
pub use self::btm_response::{
    Ieee80211ActionFrameBtmResponse, Ieee80211BtmResponse,
};
pub use self::neighbor_report_request::{
    Ieee80211ActionFrameNeighborReportRequest, Ieee80211NeighborReportRequest,
};
pub use self::neighbor_report_response::{
    Ieee80211ActionFrameNeighborReportResponse, Ieee80211NeighborReportEntry,
    Ieee80211NeighborReportResponse,
};
pub use self::other::Ieee80211ActionFrameOther;

/// A parsed IEEE 802.11 Action management frame (IEEE Std 802.11-2024
/// §9.3.3.2).
///
/// Each modelled category/action pair is a typed variant carrying the full
/// 24-byte MAC header together with the parsed Action body. Unknown pairs
/// are preserved in [`Other`](Self::Other).
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum Ieee80211ActionFrame {
    /// Radio Measurement Neighbor Report Request (category 5, action 4).
    NeighborReportRequest(Ieee80211ActionFrameNeighborReportRequest),
    /// Radio Measurement Neighbor Report Response (category 5, action 5).
    NeighborReportResponse(Ieee80211ActionFrameNeighborReportResponse),
    /// WNM BSS Transition Management Request (category 10, action 7).
    BtmRequest(Ieee80211ActionFrameBtmRequest),
    /// WNM BSS Transition Management Response (category 10, action 8).
    BtmResponse(Ieee80211ActionFrameBtmResponse),
    /// Any other category/action pair, with the raw body kept.
    Other(Ieee80211ActionFrameOther),
}

impl Ieee80211ActionFrame {
    /// Frame Control type/subtype value of a management Action frame
    /// (`IEEE80211_STYPE_ACTION`, also used by `NL80211_CMD_REGISTER_FRAME`).
    pub const FRAME_TYPE: u16 = 0x00D0;

    /// Parse a full IEEE 802.11 Action management frame.
    ///
    /// Modelled category/action pairs are decoded into their typed variant;
    /// unknown pairs and malformed typed bodies fall back to
    /// [`Other`](Self::Other).
    pub fn parse(data: &[u8]) -> Result<Self, DecodeError> {
        let (fixed, body) = parse_action_frame(data)?;
        let body = body.to_vec();
        Ok(match (fixed.category, fixed.action) {
            (
                Ieee80211NeighborReportRequest::CATEGORY,
                Ieee80211NeighborReportRequest::ACTION,
            ) => match Ieee80211NeighborReportRequest::parse(&body) {
                Some(request) => Self::NeighborReportRequest(
                    Ieee80211ActionFrameNeighborReportRequest::from_fixed(
                        fixed, body, request,
                    ),
                ),
                None => Self::Other(Ieee80211ActionFrameOther::from_fixed(
                    fixed, body,
                )),
            },
            (
                Ieee80211NeighborReportResponse::CATEGORY,
                Ieee80211NeighborReportResponse::ACTION,
            ) => match Ieee80211NeighborReportResponse::parse(&body) {
                Some(response) => Self::NeighborReportResponse(
                    Ieee80211ActionFrameNeighborReportResponse::from_fixed(
                        fixed, body, response,
                    ),
                ),
                None => Self::Other(Ieee80211ActionFrameOther::from_fixed(
                    fixed, body,
                )),
            },
            (Ieee80211BtmRequest::CATEGORY, Ieee80211BtmRequest::ACTION) => {
                match Ieee80211BtmRequest::parse(&body) {
                    Some(request) => Self::BtmRequest(
                        Ieee80211ActionFrameBtmRequest::from_fixed(
                            fixed, body, request,
                        ),
                    ),
                    None => Self::Other(Ieee80211ActionFrameOther::from_fixed(
                        fixed, body,
                    )),
                }
            }
            (Ieee80211BtmResponse::CATEGORY, Ieee80211BtmResponse::ACTION) => {
                match Ieee80211BtmResponse::parse(&body) {
                    Some(response) => Self::BtmResponse(
                        Ieee80211ActionFrameBtmResponse::from_fixed(
                            fixed, body, response,
                        ),
                    ),
                    None => Self::Other(Ieee80211ActionFrameOther::from_fixed(
                        fixed, body,
                    )),
                }
            }
            _ => {
                Self::Other(Ieee80211ActionFrameOther::from_fixed(fixed, body))
            }
        })
    }

    /// Create an unmodelled Action frame in the STA-to-AP direction.
    pub fn new(
        sta_mac: [u8; 6],
        bssid: [u8; 6],
        category: u8,
        action: u8,
        body: Vec<u8>,
    ) -> Self {
        Self::Other(Ieee80211ActionFrameOther::new(
            sta_mac, bssid, category, action, body,
        ))
    }

    /// Create a STA-to-AP Radio Measurement Neighbor Report Request Action
    /// frame.
    pub fn new_neighbor_report_request(
        sta_mac: [u8; 6],
        bssid: [u8; 6],
        request: Ieee80211NeighborReportRequest,
    ) -> Self {
        Self::NeighborReportRequest(
            Ieee80211ActionFrameNeighborReportRequest::new(
                sta_mac, bssid, request,
            ),
        )
    }

    /// Create a STA-to-AP WNM BTM Response Action frame.
    pub fn new_btm_response(
        sta_mac: [u8; 6],
        bssid: [u8; 6],
        response: Ieee80211BtmResponse,
    ) -> Self {
        Self::BtmResponse(Ieee80211ActionFrameBtmResponse::new(
            sta_mac, bssid, response,
        ))
    }

    /// The Action category octet.
    pub fn category(&self) -> u8 {
        match self {
            Self::NeighborReportRequest(_) => {
                Ieee80211NeighborReportRequest::CATEGORY
            }
            Self::NeighborReportResponse(_) => {
                Ieee80211NeighborReportResponse::CATEGORY
            }
            Self::BtmRequest(_) => Ieee80211BtmRequest::CATEGORY,
            Self::BtmResponse(_) => Ieee80211BtmResponse::CATEGORY,
            Self::Other(frame) => frame.category,
        }
    }

    /// The Action code within the category.
    pub fn action(&self) -> u8 {
        match self {
            Self::NeighborReportRequest(_) => {
                Ieee80211NeighborReportRequest::ACTION
            }
            Self::NeighborReportResponse(_) => {
                Ieee80211NeighborReportResponse::ACTION
            }
            Self::BtmRequest(_) => Ieee80211BtmRequest::ACTION,
            Self::BtmResponse(_) => Ieee80211BtmResponse::ACTION,
            Self::Other(frame) => frame.action,
        }
    }

    /// The STA MAC address in an infrastructure BSS.
    pub fn sta_mac(&self) -> [u8; 6] {
        match self {
            Self::NeighborReportRequest(frame) => frame.sta_mac(),
            Self::NeighborReportResponse(frame) => frame.sta_mac(),
            Self::BtmRequest(frame) => frame.sta_mac(),
            Self::BtmResponse(frame) => frame.sta_mac(),
            Self::Other(frame) => frame.sta_mac(),
        }
    }

    /// The raw Action body after the category and action octets.
    pub fn body(&self) -> &[u8] {
        match self {
            Self::NeighborReportRequest(frame) => frame.body(),
            Self::NeighborReportResponse(frame) => frame.body(),
            Self::BtmRequest(frame) => frame.body(),
            Self::BtmResponse(frame) => frame.body(),
            Self::Other(frame) => frame.body(),
        }
    }

    /// Serialize this frame into raw 802.11 management frame bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::NeighborReportRequest(frame) => frame.to_bytes(),
            Self::NeighborReportResponse(frame) => frame.to_bytes(),
            Self::BtmRequest(frame) => frame.to_bytes(),
            Self::BtmResponse(frame) => frame.to_bytes(),
            Self::Other(frame) => frame.to_bytes(),
        }
    }

    /// Whether this is a WNM BSS Transition Management Request.
    pub fn is_btm_request(&self) -> bool {
        matches!(self, Self::BtmRequest(_))
    }

    /// Whether this is a WNM BSS Transition Management Response.
    pub fn is_btm_response(&self) -> bool {
        matches!(self, Self::BtmResponse(_))
    }

    /// Whether this is a Radio Measurement Neighbor Report Request.
    pub fn is_neighbor_report_request(&self) -> bool {
        matches!(self, Self::NeighborReportRequest(_))
    }

    /// Whether this is a Radio Measurement Neighbor Report Response.
    pub fn is_neighbor_report_response(&self) -> bool {
        matches!(self, Self::NeighborReportResponse(_))
    }

    /// The typed full BTM Request frame, when this is a BTM Request.
    pub fn btm_request(&self) -> Option<&Ieee80211ActionFrameBtmRequest> {
        match self {
            Self::BtmRequest(frame) => Some(frame),
            _ => None,
        }
    }

    /// The typed full BTM Response frame, when this is a BTM Response.
    pub fn btm_response(&self) -> Option<&Ieee80211ActionFrameBtmResponse> {
        match self {
            Self::BtmResponse(frame) => Some(frame),
            _ => None,
        }
    }

    /// The typed full Neighbor Report Request frame, when this is one.
    pub fn neighbor_report_request(
        &self,
    ) -> Option<&Ieee80211ActionFrameNeighborReportRequest> {
        match self {
            Self::NeighborReportRequest(frame) => Some(frame),
            _ => None,
        }
    }

    /// The typed full Neighbor Report Response frame, when this is one.
    pub fn neighbor_report_response(
        &self,
    ) -> Option<&Ieee80211ActionFrameNeighborReportResponse> {
        match self {
            Self::NeighborReportResponse(frame) => Some(frame),
            _ => None,
        }
    }
}
