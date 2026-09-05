// SPDX-License-Identifier: MIT

use super::eap::Ieee80211EapolEapFrame;
use super::key::Ieee80211EapolKeyFrame;

/// A parsed IEEE 802.1X EAPOL frame received on the nl80211 control port.
///
/// The frame starts at the EAPOL protocol version byte and has no Ethernet
/// or 802.11 MAC header.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum Ieee80211EapolFrame {
    /// EAPOL type 0: an EAP packet.
    Eap(Ieee80211EapolEapFrame),
    /// EAPOL type 3: an EAPOL-Key frame.
    Key(Ieee80211EapolKeyFrame),
    /// Any other or unparseable EAPOL frame, kept as the raw PDU.
    Other(Vec<u8>),
}

impl Ieee80211EapolFrame {
    /// Parse a raw EAPOL PDU.
    pub fn parse(pdu: &[u8]) -> Self {
        if let Some(eap) = Ieee80211EapolEapFrame::parse(pdu) {
            return Self::Eap(eap);
        }
        if let Some(key) = Ieee80211EapolKeyFrame::parse(pdu) {
            return Self::Key(key);
        }
        Self::Other(pdu.to_vec())
    }
}
