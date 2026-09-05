// SPDX-License-Identifier: MIT

use netlink_packet_core::DecodeError;

use crate::Ieee80211StatusCode;

use super::capability::Ieee80211CapabilityInfo;

/// A parsed IEEE 802.11 (Re)Association Response frame body, as delivered
/// in the `NL80211_ATTR_FRAME` of an `NL80211_CMD_ASSOCIATE` event.
///
/// The frame body is (IEEE Std 802.11-2024 §9.3.3.6 Table 9-65 /
/// §9.3.3.8 Table 9-67): Capability Information(2) || Status Code(2) ||
/// AID(2) || Supported Rates ... The AID and the information elements are
/// kept as raw `remains`; Association Response and Reassociation Response
/// share this body layout.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct Ieee80211AssocRespFrame {
    /// Capability information.
    pub capability: Ieee80211CapabilityInfo,
    /// IEEE 802.11 status code.
    pub status_code: Ieee80211StatusCode,
    /// Remaining frame body after the fixed fields: AID(2) followed by the
    /// information elements.
    pub(crate) remains: Vec<u8>,
}

impl Ieee80211AssocRespFrame {
    /// Parse a (Re)Association Response frame from its raw bytes.
    ///
    /// Returns an error when the frame is shorter than the fixed 28 bytes
    /// (24-byte MAC header + capability + status code).
    pub fn parse(data: &[u8]) -> Result<Self, DecodeError> {
        if data.len() < 28 {
            return Err(DecodeError::from(format!(
                "(re)association response frame too short: {} bytes",
                data.len()
            )));
        }

        Ok(Ieee80211AssocRespFrame {
            capability: Ieee80211CapabilityInfo::from_bits_retain(
                u16::from_le_bytes([data[24], data[25]]),
            ),
            status_code: Ieee80211StatusCode::from(u16::from_le_bytes([
                data[26], data[27],
            ])),
            remains: data[28..].to_vec(),
        })
    }
}
