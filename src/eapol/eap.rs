// SPDX-License-Identifier: MIT

//! EAPOL type 0 frames (RFC 3748 / 802.1X).

const EAPOL_VERSION: u8 = 2;
const EAPOL_TYPE_EAP: u8 = 0;

/// EAPOL type 0 frame: an EAP packet wrapped in the EAPOL
/// version/type/length header.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Ieee80211EapolEapFrame {
    /// The EAP packet carried by the frame.
    pub payload: Vec<u8>,
}

impl Ieee80211EapolEapFrame {
    /// Build an EAPOL frame (version + type 0 + length) carrying an EAP
    /// packet.
    pub fn build(eap: &[u8]) -> Vec<u8> {
        let mut pdu = vec![EAPOL_VERSION, EAPOL_TYPE_EAP];
        pdu.extend_from_slice(&(eap.len() as u16).to_be_bytes());
        pdu.extend_from_slice(eap);
        pdu
    }

    /// Parse an EAPOL frame and return the EAP payload it carries.
    /// Returns `None` for non-EAP EAPOL types or truncated frames.
    pub fn parse(pdu: &[u8]) -> Option<Self> {
        if pdu.len() < 4 || pdu[1] != EAPOL_TYPE_EAP {
            return None;
        }
        let len = u16::from_be_bytes([pdu[2], pdu[3]]) as usize;
        if pdu.len() < 4 + len {
            return None;
        }
        Some(Self {
            payload: pdu[4..4 + len].to_vec(),
        })
    }
}
