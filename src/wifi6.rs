// SPDX-License-Identifier: MIT

// Hold WIFI6 (802.11ax) specific data types.

use netlink_packet_core::{DecodeError, Emitable, Parseable};

use crate::bytes::{get_bit, get_bits_as_u8, write_u16_le};

const HE_MAC_CAP_INFO_LEN: usize = 6;

/// "HE MAC Capabilities Information field"
///
/// IEEE 802.11ax-2021 section 9.4.2.248.2
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Nl80211HeMacCapInfo(pub [u8; HE_MAC_CAP_INFO_LEN]);

impl Nl80211HeMacCapInfo {
    pub const LENGTH: usize = HE_MAC_CAP_INFO_LEN;

    pub fn new(value: &[u8]) -> Self {
        let mut data = [0u8; Self::LENGTH];
        if value.len() > Self::LENGTH {
            data.copy_from_slice(&value[..Self::LENGTH]);
        } else {
            data[..value.len()].copy_from_slice(value)
        }
        Self(data)
    }

    pub fn tc_he_support(&self) -> bool {
        get_bit(&self.0, 0)
    }
    pub fn wt_requester_support(&self) -> bool {
        get_bit(&self.0, 1)
    }
    pub fn wt_responder_support(&self) -> bool {
        get_bit(&self.0, 2)
    }
    pub fn ynamic_fragmentation_support(&self) -> u8 {
        get_bits_as_u8(&self.0, 3, 4)
    }
    pub fn ax_fragmented_msdu_amsdu(&self) -> u8 {
        get_bits_as_u8(&self.0, 5, 7)
    }
    pub fn in_fragment_size(&self) -> u8 {
        get_bits_as_u8(&self.0, 8, 9)
    }
    pub fn rigger_frame_mac_pending_duration(&self) -> u8 {
        get_bits_as_u8(&self.0, 10, 11)
    }
    pub fn ulti_tid_aggregation_rx_support(&self) -> u8 {
        get_bits_as_u8(&self.0, 12, 14)
    }
    pub fn e_link_adapttion_support(&self) -> u8 {
        get_bits_as_u8(&self.0, 15, 16)
    }
    pub fn ll_ack_support(&self) -> bool {
        get_bit(&self.0, 17)
    }
    pub fn ts_support(&self) -> bool {
        get_bit(&self.0, 18)
    }
    pub fn sr_support(&self) -> bool {
        get_bit(&self.0, 19)
    }
    pub fn roadcast_twt_support(&self) -> bool {
        get_bit(&self.0, 20)
    }
    pub fn support_32_bit_ba_bitmap(&self) -> bool {
        get_bit(&self.0, 21)
    }
    pub fn u_cascading_support(&self) -> bool {
        get_bit(&self.0, 22)
    }
    pub fn ck_enabled_aggregation_support(&self) -> bool {
        get_bit(&self.0, 23)
    }
    // bit 24 is reserved
    pub fn m_control_support(&self) -> bool {
        get_bit(&self.0, 25)
    }
    pub fn fdma_ra_support(&self) -> bool {
        get_bit(&self.0, 26)
    }
    pub fn ax_a_mpdu_length_exponent_extentsion(&self) -> u8 {
        get_bits_as_u8(&self.0, 27, 28)
    }
    pub fn _msdu_fragmentation_support(&self) -> bool {
        get_bit(&self.0, 29)
    }
    pub fn lexible_twt_scheduler_support(&self) -> bool {
        get_bit(&self.0, 30)
    }
    pub fn x_control_frame_to_multibss(&self) -> bool {
        get_bit(&self.0, 31)
    }
    pub fn srp_bqrp_a_mpdu_aggregation(&self) -> bool {
        get_bit(&self.0, 32)
    }
    pub fn tp_support(&self) -> bool {
        get_bit(&self.0, 33)
    }
    pub fn qr_support(&self) -> bool {
        get_bit(&self.0, 34)
    }
    pub fn sr_responder(&self) -> bool {
        get_bit(&self.0, 35)
    }
    pub fn dp_feedback_report_support(&self) -> bool {
        get_bit(&self.0, 36)
    }
    pub fn ps_support(&self) -> bool {
        get_bit(&self.0, 37)
    }
    pub fn _msdu_not_under_ba_in_ack_enabled_a_mpdu_support(&self) -> bool {
        get_bit(&self.0, 38)
    }
    pub fn ulti_tid_aggregation_tx_support(&self) -> u8 {
        get_bits_as_u8(&self.0, 39, 41)
    }
    pub fn e_subchannel_selective_ransmission_support(&self) -> bool {
        get_bit(&self.0, 42)
    }
    pub fn l_2x_996_tone_ru_support(&self) -> bool {
        get_bit(&self.0, 43)
    }
    pub fn m_control_ul_mu_data_disable_rx_support(&self) -> bool {
        get_bit(&self.0, 44)
    }
    pub fn e_dynamic_sm_power_save(&self) -> bool {
        get_bit(&self.0, 45)
    }
    pub fn unctured_sounding_support(&self) -> bool {
        get_bit(&self.0, 46)
    }
    pub fn t_and_vht_trigger_frame_rx_support(&self) -> bool {
        get_bit(&self.0, 47)
    }
}

impl Emitable for Nl80211HeMacCapInfo {
    fn buffer_len(&self) -> usize {
        HE_MAC_CAP_INFO_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        if buffer.len() < HE_MAC_CAP_INFO_LEN {
            log::error!(
                "Buffer size is smaller than HE_MAC_CAP_INFO_LEN \
                {HE_MAC_CAP_INFO_LEN}"
            );
            return;
        }
        buffer[..Self::LENGTH].copy_from_slice(&self.0)
    }
}

const HE_PHY_CAP_INFO_LEN: usize = 11;

/// "HE PHY Capabilities Information field"
///
/// IEEE 802.11ax-2021 section 9.4.2.248.3
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Nl80211HePhyCapInfo(pub [u8; HE_PHY_CAP_INFO_LEN]);

impl Nl80211HePhyCapInfo {
    pub const LENGTH: usize = HE_PHY_CAP_INFO_LEN;

    pub fn new(value: &[u8]) -> Self {
        let mut data = [0u8; Self::LENGTH];
        if value.len() > Self::LENGTH {
            data.copy_from_slice(&value[..Self::LENGTH]);
        } else {
            data[..value.len()].copy_from_slice(value)
        }
        Self(data)
    }

    pub fn supported_channel_width_set(&self) -> u8 {
        get_bits_as_u8(&self.0, 1, 7)
    }

    // TODO: Add all fields as functions by checking 802.11ax-2021
}

impl Emitable for Nl80211HePhyCapInfo {
    fn buffer_len(&self) -> usize {
        HE_PHY_CAP_INFO_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        if buffer.len() < HE_PHY_CAP_INFO_LEN {
            log::error!(
                "Buffer size is smaller than HE_PHY_CAP_INFO_LEN \
                {HE_PHY_CAP_INFO_LEN}"
            );
            return;
        }
        buffer[..HE_PHY_CAP_INFO_LEN].copy_from_slice(&self.0)
    }
}

const NL80211_HE_MCS_NSS_SUPP_LEN: usize = 12;

/// Tx/Rx HE MCS NSS Support Field
///
/// The released 802.11ax-2021 has no `Tx/Rx HE MCS NSS Support` section, this
/// struct is merely copy of linux kernel `struct ieee80211_he_mcs_nss_supp`.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct Nl80211HeMcsNssSupp {
    /// Rx MCS map 2 bits for each stream, total 8 streams, for channel widths
    /// less than 80MHz.
    pub rx_mcs_80: u16,
    /// Tx MCS map 2 bits for each stream, total 8 streams, for channel widths
    /// less than 80MHz.
    pub tx_mcs_80: u16,
    /// Rx MCS map 2 bits for each stream, total 8 streams, for channel width
    /// 160MHz.
    pub rx_mcs_160: u16,
    /// Tx MCS map 2 bits for each stream, total 8 streams, for channel width
    /// 160MHz.
    pub tx_mcs_160: u16,
    /// Rx MCS map 2 bits for each stream, total 8 streams, for channel width
    /// 80p80MHz.
    pub rx_mcs_80p80: u16,
    /// Tx MCS map 2 bits for each stream, total 8 streams, for channel width
    /// 80p80MHz.
    pub tx_mcs_80p80: u16,
}

impl Nl80211HeMcsNssSupp {
    pub const LENGTH: usize = NL80211_HE_MCS_NSS_SUPP_LEN;
}

impl Emitable for Nl80211HeMcsNssSupp {
    fn buffer_len(&self) -> usize {
        NL80211_HE_MCS_NSS_SUPP_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        if buffer.len() < NL80211_HE_MCS_NSS_SUPP_LEN {
            log::error!(
                "Buffer size is smaller than NL80211_HE_MCS_NSS_SUPP_LEN \
                {NL80211_HE_MCS_NSS_SUPP_LEN}"
            );
            return;
        }
        write_u16_le(&mut buffer[0..2], self.rx_mcs_80);
        write_u16_le(&mut buffer[2..4], self.tx_mcs_80);
        write_u16_le(&mut buffer[4..6], self.rx_mcs_160);
        write_u16_le(&mut buffer[6..8], self.tx_mcs_160);
        write_u16_le(&mut buffer[8..10], self.rx_mcs_80p80);
        write_u16_le(&mut buffer[10..12], self.tx_mcs_80p80);
    }
}

impl<T: AsRef<[u8]> + ?Sized> Parseable<T> for Nl80211HeMcsNssSupp {
    fn parse(buf: &T) -> Result<Self, DecodeError> {
        let buf: &[u8] = buf.as_ref();
        if buf.len() < Self::LENGTH {
            Err(format!(
                "Expecting `struct ieee80211_he_mcs_nss_supp` u8 array \
                 with size {}, but got length {}",
                Self::LENGTH,
                buf.len()
            )
            .into())
        } else {
            Ok(Self {
                rx_mcs_80: u16::from_le_bytes([buf[0], buf[1]]),
                tx_mcs_80: u16::from_le_bytes([buf[2], buf[3]]),
                rx_mcs_160: u16::from_le_bytes([buf[4], buf[5]]),
                tx_mcs_160: u16::from_le_bytes([buf[6], buf[7]]),
                rx_mcs_80p80: u16::from_le_bytes([buf[8], buf[9]]),
                tx_mcs_80p80: u16::from_le_bytes([buf[10], buf[11]]),
            })
        }
    }
}

// Kernel says the maximum is 25, but my(Gris Ge) understanding of IEEE
// 802.11ax-2021 indicate the maximum size is:
//      ((NSTS + 1) * 6 * 4 + 4 + 3 ) / 8 + 1   == 28 bytes
//                    |   |   |   |
//                    |   |   |   +---- NSTS
//                    |   |   +------ RU index bitmask(4 bits)
//                    |   +--- RU allocation index, 4 combination
//                    |
//                    +---- PPET 16 (3 bits) and PPET 8 (3 bits)
//
// The 25 bytes could be using `NSTS` instead of `NSTS +1`.
//
const IEEE80211_HE_PPE_THRES_MAX_LEN: usize = 25;

/// IEEE 802.11ax-2021 section 9.4.2.248.5
/// "PPE Thresholds field"
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Nl80211HePpeThreshold(pub [u8; IEEE80211_HE_PPE_THRES_MAX_LEN]);

impl Nl80211HePpeThreshold {
    pub const LENGTH: usize = IEEE80211_HE_PPE_THRES_MAX_LEN;

    pub fn new(value: &[u8]) -> Self {
        let mut data = [0u8; Self::LENGTH];
        if value.len() > Self::LENGTH {
            data.copy_from_slice(&value[..Self::LENGTH]);
        } else {
            data[..value.len()].copy_from_slice(value)
        }
        Self(data)
    }

    pub fn nsts(&self) -> u8 {
        get_bits_as_u8(&self.0, 0, 2)
    }

    pub fn ru_index_bitmask(&self) -> u8 {
        get_bits_as_u8(&self.0, 3, 6)
    }

    // TODO, add iterator to access thresholds
}

impl Emitable for Nl80211HePpeThreshold {
    fn buffer_len(&self) -> usize {
        IEEE80211_HE_PPE_THRES_MAX_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        if buffer.len() < IEEE80211_HE_PPE_THRES_MAX_LEN {
            log::error!(
                "Buffer size is smaller than IEEE80211_HE_PPE_THRES_MAX_LEN \
                {IEEE80211_HE_PPE_THRES_MAX_LEN}"
            );
            return;
        }
        buffer[..IEEE80211_HE_PPE_THRES_MAX_LEN].copy_from_slice(&self.0)
    }
}

/* HE 6 GHz band capabilities */
// const IEEE80211_HE_6GHZ_CAP_MIN_MPDU_START: u16 = 0x0007;
// const IEEE80211_HE_6GHZ_CAP_MAX_AMPDU_LEN_EXP: u16 = 0x0038;
// const IEEE80211_HE_6GHZ_CAP_MAX_MPDU_LEN: u16 = 0x00c0;
// const IEEE80211_HE_6GHZ_CAP_SM_PS: u16 = 0x0600;
// const IEEE80211_HE_6GHZ_CAP_RD_RESPONDER: u16 = 0x0800;
// const IEEE80211_HE_6GHZ_CAP_RX_ANTPAT_CONS: u16 = 0x1000;
// const IEEE80211_HE_6GHZ_CAP_TX_ANTPAT_CONS: u16 = 0x2000;

const IEEE80211_HE_6GHZ_CAP_LEN: usize = 2;

/// "HE 6 GHz Band Capabilities element"
///
/// IEEE 802.11ax-2021 section 9.4.2.263
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Nl80211He6GhzCapa(pub [u8; IEEE80211_HE_6GHZ_CAP_LEN]);

impl Nl80211He6GhzCapa {
    pub const LENGTH: usize = IEEE80211_HE_6GHZ_CAP_LEN;

    pub fn new(value: &[u8]) -> Self {
        let mut data = [0u8; Self::LENGTH];
        if value.len() > Self::LENGTH {
            data.copy_from_slice(&value[..Self::LENGTH]);
        } else {
            data[..value.len()].copy_from_slice(value)
        }
        Self(data)
    }

    pub fn minimum_mpdu_start_spacing(&self) -> u8 {
        get_bits_as_u8(&self.0, 0, 2)
    }

    pub fn maximum_a_mpdu_length_exponent(&self) -> u8 {
        get_bits_as_u8(&self.0, 3, 5)
    }

    pub fn maximum_mpdu_length(&self) -> u8 {
        get_bits_as_u8(&self.0, 6, 7)
    }

    pub fn sm_power_save(&self) -> u8 {
        get_bits_as_u8(&self.0, 9, 10)
    }

    pub fn rd_responder(&self) -> bool {
        get_bit(&self.0, 11)
    }

    pub fn rx_antenna_pattern_consistency(&self) -> bool {
        get_bit(&self.0, 12)
    }

    pub fn tx_antenna_pattern_consistency(&self) -> bool {
        get_bit(&self.0, 12)
    }
}

impl Emitable for Nl80211He6GhzCapa {
    fn buffer_len(&self) -> usize {
        IEEE80211_HE_6GHZ_CAP_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        if buffer.len() < IEEE80211_HE_6GHZ_CAP_LEN {
            log::error!(
                "Buffer size is smaller than IEEE80211_HE_6GHZ_CAP_LEN \
                {IEEE80211_HE_6GHZ_CAP_LEN}"
            );
            return;
        }
        buffer[..IEEE80211_HE_6GHZ_CAP_LEN].copy_from_slice(&self.0)
    }
}
