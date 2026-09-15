// SPDX-License-Identifier: MIT

//! EAPOL-Key key data KDEs and IEs (IEEE 802.11-2020 §12.7.2).
//!
//! The (decrypted) key data field of the 4-way handshake Message 3 and
//! of the group-key handshake is a sequence of KDEs - vendor elements
//! with the IEEE OUI 00-0F-AC or the WFA OUI 50-6F-9A - and plain
//! information elements. The parsers here extract the GTK, IGTK and
//! BIGTK KDEs, the WFA Transition Disable KDE, the Extended Key ID KDE,
//! the AP's RSNE / RSNXE and the Operating Channel Information (OCI)
//! KDE used by Operating Channel Validation. The key itself is not
//! touched: unwrapping the GTK and the handshake state machine stay with
//! the caller.

use std::mem::size_of;

use netlink_packet_core::DecodeError;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::element::{
    Ieee80211ElementBuffer, ELEMENT_ID_RSN, ELEMENT_ID_RSN_EXT,
    ELEMENT_ID_VENDOR,
};

/// The IEEE (802.11) OUI carried by the KDEs defined in IEEE
/// 802.11-2020 §12.7.2.
const KDE_OUI: [u8; 3] = [0x00, 0x0F, 0xAC];
/// The Wi-Fi Alliance OUI, used by the Transition Disable KDE.
const WFA_OUI: [u8; 3] = [0x50, 0x6F, 0x9A];
const KDE_TYPE_GTK: u8 = 1;
const KDE_TYPE_IGTK: u8 = 9;
const KDE_TYPE_KEY_ID: u8 = 10;
/// KDE type of the OCI (Operating Channel Information) KDE.
const KDE_TYPE_OCI: u8 = 13;
const KDE_TYPE_BIGTK: u8 = 14;
const WFA_KDE_TYPE_TRANSITION_DISABLE: u8 = 0x20;

/// Raw wire layout of an Operating Channel Information (OCI) KDE
/// payload (IEEE 802.11-2020 §12.7.2.3, KDE type 13):
///
/// ```text
/// Operating Class (1) | Channel Number (1) | Channel Width Segment (1)
/// ```
#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    Copy,
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
)]
#[repr(C, packed)]
pub struct Ieee80211OciBuffer {
    /// Global operating class (802.11-2020 Annex E, Table E-1).
    pub operating_class: u8,
    /// Primary channel number.
    pub channel: u8,
    /// Channel-width segment index (0 for a 20 MHz channel).
    pub segment: u8,
}

impl Ieee80211OciBuffer {
    /// Number of octets of an OCI payload.
    pub const LEN: usize = size_of::<Self>();

    /// The OCI payload of an operating class, channel and segment.
    pub fn new(operating_class: u8, channel: u8, segment: u8) -> Self {
        Self {
            operating_class,
            channel,
            segment,
        }
    }

    /// Split `buf` (the start of an OCI payload) into the OCI and the
    /// octets that follow it.
    ///
    /// An error is returned when `buf` does not hold a complete OCI
    /// payload.
    pub fn split(buf: &[u8]) -> Result<(&Self, &[u8]), DecodeError> {
        Self::ref_from_prefix(buf)
            .map_err(|_| DecodeError::buffer_too_small(buf.len(), Self::LEN))
    }
}

/// Operating Channel Information (OCI) KDE payload: the operating
/// class, the channel number and the channel-width segment of the
/// sender's channel (IEEE 802.11-2020 §12.7.2.3, KDE type 13). Carried
/// in the key data of EAPOL-Key Message 2 (by the STA) and Message 3
/// (by the AP) when Operating Channel Validation is enabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ieee80211Oci {
    /// Global operating class (802.11-2020 Annex E, Table E-1).
    pub operating_class: u8,
    /// Primary channel number.
    pub channel: u8,
    /// Channel-width segment index (0 for a 20 MHz channel).
    pub segment: u8,
}

impl Ieee80211Oci {
    /// Length of the OCI payload: operating class (1) || channel (1) ||
    /// segment (1).
    pub const LENGTH: usize = Ieee80211OciBuffer::LEN;

    /// Derive the OCI (operating class, channel, segment 0) for a BSS
    /// frequency. 20 MHz primary-channel mapping only: 2.4 GHz uses
    /// operating class 81 (channels 1-13), 5 GHz uses the global
    /// operating classes 115-118 by channel range. Frequencies without a
    /// mapping (e.g. 6 GHz or the 5 MHz 2.4 GHz channel 14) return
    /// `None`.
    pub fn from_freq(freq_mhz: u32) -> Option<Self> {
        if (2412..=2472).contains(&freq_mhz) && (freq_mhz - 2407) % 5 == 0 {
            let channel = ((freq_mhz - 2407) / 5) as u8;
            return Some(Self {
                operating_class: 81,
                channel,
                segment: 0,
            });
        }
        if freq_mhz >= 5000 && (freq_mhz - 5000) % 5 == 0 {
            let channel = ((freq_mhz - 5000) / 5) as u8;
            let operating_class = match channel {
                36..=48 => 115,
                52..=64 => 116,
                100..=144 => 117,
                149..=177 => 118,
                _ => return None,
            };
            return Some(Self {
                operating_class,
                channel,
                segment: 0,
            });
        }
        None
    }

    /// The OCI payload octets, as they appear after the KDE's OUI and
    /// type octets.
    pub fn to_bytes(self) -> [u8; Self::LENGTH] {
        let mut octets = [0u8; Self::LENGTH];
        octets.copy_from_slice(Ieee80211OciBuffer::from(self).as_bytes());
        octets
    }

    /// Whether this OCI refers to the same primary channel as the given
    /// frequency: the channel must map to the same primary frequency.
    /// The segment (channel width) is not checked - a 20 MHz STA
    /// assumption.
    pub fn matches_freq(self, freq_mhz: u32) -> bool {
        Self::from_freq(freq_mhz)
            .is_some_and(|expected| self.channel == expected.channel)
    }
}

impl From<[u8; Ieee80211Oci::LENGTH]> for Ieee80211Oci {
    fn from(octets: [u8; Ieee80211Oci::LENGTH]) -> Self {
        let (oci, _) = Ieee80211OciBuffer::split(&octets)
            .expect("an OCI payload is exactly 3 octets");
        Self::from(*oci)
    }
}

impl From<Ieee80211OciBuffer> for Ieee80211Oci {
    fn from(oci: Ieee80211OciBuffer) -> Self {
        Self {
            operating_class: oci.operating_class,
            channel: oci.channel,
            segment: oci.segment,
        }
    }
}

impl From<Ieee80211Oci> for Ieee80211OciBuffer {
    fn from(oci: Ieee80211Oci) -> Self {
        Self {
            operating_class: oci.operating_class,
            channel: oci.channel,
            segment: oci.segment,
        }
    }
}

/// Raw wire layout of an OCI key data element (IEEE 802.11-2020
/// §12.7.2.3):
///
/// ```text
/// Element ID (1) | Length (1) | OUI (3) | Type (1) | OCI (3)
/// ```
///
/// The Element ID is [`ELEMENT_ID_VENDOR`], the OUI is [`KDE_OUI`], the
/// type is 13, and the Length field counts the OUI, the type and the OCI
/// payload.
#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    Copy,
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
)]
#[repr(C, packed)]
pub struct Ieee80211OciKeyDataElemBuffer {
    element_id: u8,
    length: u8,
    oui: [u8; 3],
    kde_type: u8,
    oci: Ieee80211OciBuffer,
}

impl Ieee80211OciKeyDataElemBuffer {
    /// Number of octets of an OCI key data element.
    pub const LEN: usize = size_of::<Self>();

    /// The Length field of an OCI key data element.
    const LENGTH: u8 = (Self::LEN - Ieee80211ElementBuffer::LEN) as u8;

    /// The OCI key data element carrying `oci`.
    pub fn new(oci: Ieee80211Oci) -> Self {
        Self {
            element_id: ELEMENT_ID_VENDOR,
            length: Self::LENGTH,
            oui: KDE_OUI,
            kde_type: KDE_TYPE_OCI,
            oci: oci.into(),
        }
    }

    /// The OCI this key data element carries.
    pub fn oci(&self) -> Ieee80211Oci {
        self.oci.into()
    }

    /// Split `buf` (the start of an information element) into the OCI
    /// key data element and the octets that follow it.
    ///
    /// An error is returned when `buf` does not hold a complete OCI key
    /// data element or holds another element.
    pub fn split(buf: &[u8]) -> Result<(&Self, &[u8]), DecodeError> {
        let (kde, rest) = Self::ref_from_prefix(buf)
            .map_err(|_| DecodeError::buffer_too_small(buf.len(), Self::LEN))?;
        let (element_id, length, oui, kde_type) =
            (kde.element_id, kde.length, kde.oui, kde.kde_type);
        if element_id != ELEMENT_ID_VENDOR
            || length != Self::LENGTH
            || oui != KDE_OUI
            || kde_type != KDE_TYPE_OCI
        {
            return Err(DecodeError::from(format!(
                "Not an OCI key data element: Element ID {element_id}, \
                 Length {length}, OUI {oui:02x?}, type {kde_type}"
            )));
        }
        Ok((kde, rest))
    }
}

/// An IGTK or BIGTK extracted from its EAPOL-Key key data KDE: key index,
/// the 6-octet IPN (initial packet number = RX sequence counter) and the
/// key itself (802.11-2020 §12.7.2, KDE types 9 and 10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ieee80211MgmtKeyKde {
    pub key_index: u8,
    pub ipn: [u8; 6],
    pub key: Vec<u8>,
}

/// The KDEs / IEs parsed out of a decrypted EAPOL-Key key data field
/// (Message 3 of the 4-way handshake, or the group-key handshake).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ieee80211KeyDataKdes {
    /// GTK KDE (type 1): (key index, GTK).
    pub gtk: Option<(u8, Vec<u8>)>,
    /// IGTK KDE (type 9), present on every PMF AP.
    pub igtk: Option<Ieee80211MgmtKeyKde>,
    /// BIGTK KDE (type 10), present when the AP enables beacon
    /// protection.
    pub bigtk: Option<Ieee80211MgmtKeyKde>,
    /// The AP's RSNE as a full element (ID + length + body).
    pub rsne: Option<Vec<u8>>,
    /// The AP's RSNXE as a full element (ID 244 + length + body).
    pub rsnxe: Option<Vec<u8>>,
    /// Extended Key ID KDE (type 10): the pairwise key id (0/1) the AP
    /// selected.
    pub key_id: Option<u8>,
    /// Transition Disable KDE bitmap (WFA OUI 50:6F:9A, type 0x20):
    /// bit 0 = WPA3-Personal, 1 = SAE-PK, 2 = WPA3-Enterprise,
    /// 3 = Enhanced Open.
    pub transition_disable: Option<u8>,
}

/// Parse the (decrypted) EAPOL-Key key data of Message 3: a sequence of
/// KDEs (vendor elements with OUI 00-0F-AC or 50-6F-9A) and plain IEs.
/// Collects the GTK, IGTK and BIGTK KDEs plus the AP's RSNE / RSNXE for
/// the downgrade check. Malformed trailing data ends the parse; unknown
/// KDEs are skipped.
pub fn parse_key_data_kdes(key_data: &[u8]) -> Ieee80211KeyDataKdes {
    let mut kdes = Ieee80211KeyDataKdes::default();
    let mut pos = 0;
    while pos + 2 <= key_data.len() {
        let id = key_data[pos];
        let len = key_data[pos + 1] as usize;
        let body_start = pos + 2;
        let body_end = body_start + len;
        if body_end > key_data.len() {
            break;
        }
        let body = &key_data[body_start..body_end];
        match id {
            ELEMENT_ID_VENDOR if body.len() >= 4 && body[..3] == WFA_OUI => {
                // WFA vendor KDEs: Transition Disable (type 0x20)
                // carries a bitmap after the OUI + type.
                if body[3] == WFA_KDE_TYPE_TRANSITION_DISABLE && body.len() >= 5
                {
                    kdes.transition_disable = Some(body[4]);
                }
            }
            ELEMENT_ID_VENDOR if body.len() >= 4 && body[..3] == KDE_OUI => {
                let data_type = body[3];
                match data_type {
                    KDE_TYPE_GTK => {
                        // body: OUI(3) type(1) keyinfo(1) reserved(1)
                        // GTK(..)
                        if body.len() >= 7 {
                            let key_id = body[4] & 0x03;
                            let gtk = body[6..].to_vec();
                            if !gtk.is_empty() {
                                kdes.gtk = Some((key_id, gtk));
                            }
                        }
                    }
                    KDE_TYPE_IGTK | KDE_TYPE_BIGTK
                        if body.len() >= 4 + 8 + 16 =>
                    {
                        // body: OUI(3) type(1) KeyID(2 LE) IPN(6) Key(..)
                        let mgmt_key = Ieee80211MgmtKeyKde {
                            key_index: u16::from_le_bytes([body[4], body[5]])
                                as u8,
                            ipn: [
                                body[6], body[7], body[8], body[9], body[10],
                                body[11],
                            ],
                            key: body[12..].to_vec(),
                        };
                        if data_type == KDE_TYPE_IGTK {
                            kdes.igtk = Some(mgmt_key);
                        } else {
                            kdes.bigtk = Some(mgmt_key);
                        }
                    }
                    KDE_TYPE_KEY_ID if body.len() >= 5 => {
                        // Key ID KDE: OUI(3) type(1) key_id(2 LE); only
                        // the low two bits of the first octet are used.
                        kdes.key_id = Some(body[4] & 0x03);
                    }
                    _ => {}
                }
            }
            ELEMENT_ID_RSN => {
                kdes.rsne = Some(key_data[pos..body_end].to_vec())
            }
            ELEMENT_ID_RSN_EXT => {
                kdes.rsnxe = Some(key_data[pos..body_end].to_vec())
            }
            _ => {}
        }
        pos = body_end;
    }
    kdes
}

/// Parse a GTK KDE from (decrypted) EAPOL-Key key data. Returns the key
/// index and the GTK. Key data is a sequence of KDEs/IEs; the GTK KDE
/// has element id 0xDD, OUI 00-0F-AC, data type 1, followed by a
/// key-info octet (low 2 bits = key id), a reserved octet, then the GTK.
pub fn parse_gtk_kde(key_data: &[u8]) -> Option<(u8, Vec<u8>)> {
    parse_key_data_kdes(key_data).gtk
}

/// Build the OCI KDE carried in EAPOL-Key key data: element `DD`, OUI
/// 00:0F:AC, type 13 (RSN_KEY_DATA_OCI), then the 3 OCI octets.
pub fn build_oci_kde(oci: Ieee80211Oci) -> Vec<u8> {
    Ieee80211OciKeyDataElemBuffer::new(oci).as_bytes().to_vec()
}

/// Parse an OCI KDE (OUI 00-0F-AC, type 13) out of key data.
pub fn parse_oci_kde(key_data: &[u8]) -> Option<Ieee80211Oci> {
    let mut pos = 0;
    while let Ok((element, _)) = Ieee80211ElementBuffer::split(&key_data[pos..])
    {
        if let Ok((kde, _)) =
            Ieee80211OciKeyDataElemBuffer::split(&key_data[pos..])
        {
            return Some(kde.oci());
        }
        pos += element.buffer_len();
    }
    None
}
