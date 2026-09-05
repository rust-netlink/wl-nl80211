// SPDX-License-Identifier: MIT

//! EAPOL-Key PDU parsing and building (IEEE 802.1X-2010 §11.9).
//!
//! These operate on the raw 802.1X (EAPOL) PDU starting at the protocol
//! version byte, WITHOUT any Ethernet header. This matches the frame format
//! used by control-port-over-nl80211 (NL80211_CMD_CONTROL_PORT_FRAME), where
//! the source MAC and EtherType are carried in separate netlink attributes.
//! The 4-way handshake MIC is also computed over this exact PDU (with the
//! MIC field zeroed).

const EAPOL_VERSION: u8 = 2;
const EAPOL_TYPE_KEY: u8 = 3;
const EAPOL_KEY_DESCRIPTOR_RSN: u8 = 2;

// Offsets within the EAPOL-Key PDU (from the version byte).
const EAPOL_HDR_LEN: usize = 4; // version, type, length(2)
const OFF_KEY_INFO: usize = EAPOL_HDR_LEN + 1; // after descriptor type
const OFF_REPLAY: usize = OFF_KEY_INFO + 2 + 2; // after key_info, key_len
const OFF_NONCE: usize = OFF_REPLAY + 8;
const OFF_IV: usize = OFF_NONCE + 32;
const OFF_RSC: usize = OFF_IV + 16;
const OFF_ID: usize = OFF_RSC + 8;
pub(crate) const OFF_MIC: usize = OFF_ID + 8; // 81
const OFF_DATA_LEN: usize = OFF_MIC + 16; // 97
const KEY_DESC_HDR_LEN: usize = OFF_DATA_LEN + 2 - EAPOL_HDR_LEN; // 95

// Key Information bit positions (16-bit field, big-endian on the wire)
const KEY_INFO_DESC_TYPE_MASK: u16 = 0x0007;
const KEY_INFO_PAIRWISE: u16 = 0x0008;
const KEY_INFO_INSTALL: u16 = 0x0040;
const KEY_INFO_ACK: u16 = 0x0080;
const KEY_INFO_MIC: u16 = 0x0100;
const KEY_INFO_SECURE: u16 = 0x0200;
const KEY_INFO_REQUEST: u16 = 0x0800;
const KEY_INFO_ENCRYPTED_DATA: u16 = 0x1000;

/// EAPOL-Key frame parsed fields.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Ieee80211EapolKeyFrame {
    pub key_info: u16,
    pub replay_counter: u64,
    pub key_nonce: [u8; 32],
    pub key_rsc: [u8; 8],
    pub key_mic: [u8; 16],
    pub key_data: Vec<u8>,
    /// The full received PDU bytes (version byte onwards).
    pub raw: Vec<u8>,
}

impl Ieee80211EapolKeyFrame {
    pub fn is_pairwise(&self) -> bool {
        self.key_info & KEY_INFO_PAIRWISE != 0
    }

    pub fn has_ack(&self) -> bool {
        self.key_info & KEY_INFO_ACK != 0
    }

    pub fn has_mic(&self) -> bool {
        self.key_info & KEY_INFO_MIC != 0
    }

    pub fn is_secure(&self) -> bool {
        self.key_info & KEY_INFO_SECURE != 0
    }

    /// The Request bit: the AP asks the supplicant to initiate a
    /// handshake. Supplicants drop these frames (both wpa_supplicant and
    /// iwd do); shuli never starts a handshake on its own either.
    pub fn is_request(&self) -> bool {
        self.key_info & KEY_INFO_REQUEST != 0
    }

    pub fn is_encrypted_data(&self) -> bool {
        self.key_info & KEY_INFO_ENCRYPTED_DATA != 0
    }

    /// Key Descriptor Version (bits 0-2 of Key Information): 0 = AKM-defined,
    /// 2 = HMAC-SHA1 MIC, 3 = AES-128-CMAC MIC. The supplicant echoes the
    /// version negotiated by the AP's Message 1.
    pub fn desc_version(&self) -> u16 {
        self.key_info & KEY_INFO_DESC_TYPE_MASK
    }

    /// Parse a raw EAPOL-Key PDU (no Ethernet header).
    pub fn parse(pdu: &[u8]) -> Option<Self> {
        if pdu.len() < EAPOL_HDR_LEN + KEY_DESC_HDR_LEN {
            return None;
        }

        let _version = pdu[0];
        if pdu[1] != EAPOL_TYPE_KEY {
            return None;
        }

        let key = &pdu[EAPOL_HDR_LEN..];
        if key[0] != EAPOL_KEY_DESCRIPTOR_RSN {
            return None;
        }

        let key_info = u16::from_be_bytes([key[1], key[2]]);
        let replay_counter = u64::from_be_bytes([
            key[5], key[6], key[7], key[8], key[9], key[10], key[11], key[12],
        ]);

        let mut key_nonce = [0u8; 32];
        key_nonce.copy_from_slice(&key[13..45]);
        let mut key_rsc = [0u8; 8];
        key_rsc.copy_from_slice(&key[61..69]);
        let mut key_mic = [0u8; 16];
        key_mic.copy_from_slice(&key[77..93]);

        let key_data_len = u16::from_be_bytes([key[93], key[94]]) as usize;
        let key_data = key
            .get(95..95 + key_data_len)
            .map(|s| s.to_vec())
            .unwrap_or_default();

        Some(Self {
            key_info,
            replay_counter,
            key_nonce,
            key_rsc,
            key_mic,
            key_data,
            raw: pdu.to_vec(),
        })
    }

    /// Build a raw EAPOL-Key PDU (no Ethernet header). The MIC field is
    /// filled from `key_mic` as given; callers that need a valid MIC should
    /// build with a zero MIC, compute the MIC over the PDU, then patch
    /// [`OFF_MIC`].
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        key_info: u16,
        key_len: u16,
        replay_counter: u64,
        key_nonce: &[u8; 32],
        key_iv: &[u8; 16],
        key_rsc: &[u8; 8],
        key_id: &[u8; 8],
        key_mic: &[u8; 16],
        key_data: &[u8],
    ) -> Vec<u8> {
        let body_len = (KEY_DESC_HDR_LEN + key_data.len()) as u16;
        let mut pdu = Vec::with_capacity(EAPOL_HDR_LEN + body_len as usize);

        // EAPOL header
        pdu.push(EAPOL_VERSION);
        pdu.push(EAPOL_TYPE_KEY);
        pdu.extend_from_slice(&body_len.to_be_bytes());

        // EAPOL-Key body
        pdu.push(EAPOL_KEY_DESCRIPTOR_RSN);
        pdu.extend_from_slice(&key_info.to_be_bytes());
        pdu.extend_from_slice(&key_len.to_be_bytes());
        pdu.extend_from_slice(&replay_counter.to_be_bytes());
        pdu.extend_from_slice(key_nonce);
        pdu.extend_from_slice(key_iv);
        pdu.extend_from_slice(key_rsc);
        pdu.extend_from_slice(key_id);
        pdu.extend_from_slice(key_mic);
        pdu.extend_from_slice(&(key_data.len() as u16).to_be_bytes());
        pdu.extend_from_slice(key_data);

        pdu
    }

    /// Build 4-way handshake Message 2 (SNonce + RSNE), MIC field zeroed.
    pub fn build_message_2(
        snonce: &[u8; 32],
        replay_counter: u64,
        rsne: &[u8],
        desc_version: u16,
    ) -> Vec<u8> {
        let key_info = KEY_INFO_PAIRWISE | KEY_INFO_MIC | desc_version;
        Self::build(
            key_info,
            0,
            replay_counter,
            snonce,
            &[0u8; 16],
            &[0u8; 8],
            &[0u8; 8],
            &[0u8; 16],
            rsne,
        )
    }

    /// Build 4-way handshake Message 4 (final ACK), MIC field zeroed.
    pub fn build_message_4(
        snonce: &[u8; 32],
        replay_counter: u64,
        desc_version: u16,
    ) -> Vec<u8> {
        let key_info =
            KEY_INFO_PAIRWISE | KEY_INFO_MIC | KEY_INFO_SECURE | desc_version;
        Self::build(
            key_info,
            0,
            replay_counter,
            snonce,
            &[0u8; 16],
            &[0u8; 8],
            &[0u8; 8],
            &[0u8; 16],
            b"",
        )
    }

    /// Build the Group Key Handshake Message 2 (STA -> AP reply to a GTK
    /// rekey), MIC field zeroed. This is a group-type EAPOL-Key frame (the
    /// Pairwise bit is clear) carrying no key data; `key_rsc` echoes the
    /// group key RSC from Message 1.
    pub fn build_group_message_2(
        replay_counter: u64,
        key_rsc: &[u8; 8],
        desc_version: u16,
    ) -> Vec<u8> {
        let key_info = KEY_INFO_MIC | KEY_INFO_SECURE | desc_version;
        Self::build(
            key_info,
            0,
            replay_counter,
            &[0u8; 32],
            &[0u8; 16],
            key_rsc,
            &[0u8; 8],
            &[0u8; 16],
            b"",
        )
    }

    /// Return a copy of `pdu` with the 16-byte MIC field zeroed (for MIC
    /// computation/verification).
    pub fn pdu_with_zeroed_mic(pdu: &[u8]) -> Vec<u8> {
        let mut buf = pdu.to_vec();
        if buf.len() >= OFF_MIC + 16 {
            buf[OFF_MIC..OFF_MIC + 16].fill(0);
        }
        buf
    }

    /// Set the MIC field in a PDU in place.
    pub fn set_mic(pdu: &mut [u8], mic: &[u8; 16]) {
        if pdu.len() >= OFF_MIC + 16 {
            pdu[OFF_MIC..OFF_MIC + 16].copy_from_slice(mic);
        }
    }

    /// Format the Key Information field for logs, e.g. `desc=3 pairwise mic
    /// secure`.
    pub fn fmt_key_info(&self) -> String {
        let key_info = self.key_info;
        let desc = key_info & KEY_INFO_DESC_TYPE_MASK;
        let mut s = format!("desc={desc}");
        for (bit, name) in [
            (KEY_INFO_PAIRWISE, "pairwise"),
            (KEY_INFO_INSTALL, "install"),
            (KEY_INFO_ACK, "ack"),
            (KEY_INFO_MIC, "mic"),
            (KEY_INFO_SECURE, "secure"),
            (KEY_INFO_REQUEST, "request"),
            (KEY_INFO_ENCRYPTED_DATA, "enc-data"),
        ] {
            if key_info & bit != 0 {
                s.push(' ');
                s.push_str(name);
            }
        }
        s
    }
}
