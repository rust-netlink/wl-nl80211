// SPDX-License-Identifier: MIT

// Hold WIFI 5(802.11ac) specific data types

use anyhow::Context;
use netlink_packet_utils::{
    parsers::parse_u32, DecodeError, Emitable, Parseable,
};

use crate::bytes::write_u16_le;

const NL80211_BAND_VHT_MCS_INFO_LEN: usize = 8;

// We cannot use buffer! macro here as these u16 are all little endian while
// The `buffer!` does not support little endian yet.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Nl80211VhtMcsInfo {
    pub rx_mcs_map: u16,
    pub rx_highest: u16,
    pub tx_mcs_map: u16,
    pub tx_highest: u16,
}

impl Nl80211VhtMcsInfo {
    // `struct ieee80211_vht_mcs_info`
    // Kernel document confirmed this is 32 bytes
    pub const LENGTH: usize = NL80211_BAND_VHT_MCS_INFO_LEN;
}

impl Emitable for Nl80211VhtMcsInfo {
    fn buffer_len(&self) -> usize {
        Self::LENGTH
    }

    fn emit(&self, buffer: &mut [u8]) {
        if buffer.len() < NL80211_BAND_VHT_MCS_INFO_LEN {
            log::error!(
                "Buffer size is smaller than NL80211_BAND_VHT_MCS_INFO_LEN \
                {NL80211_BAND_VHT_MCS_INFO_LEN}"
            );
            return;
        }
        write_u16_le(&mut buffer[0..2], self.rx_mcs_map);
        write_u16_le(&mut buffer[2..4], self.rx_highest);
        write_u16_le(&mut buffer[4..6], self.tx_mcs_map);
        write_u16_le(&mut buffer[6..8], self.tx_highest);
    }
}

impl<T: AsRef<[u8]> + ?Sized> Parseable<T> for Nl80211VhtMcsInfo {
    fn parse(buf: &T) -> Result<Self, DecodeError> {
        let buf: &[u8] = buf.as_ref();
        if buf.len() < NL80211_BAND_VHT_MCS_INFO_LEN {
            return Err(format!(
                "Expecting `struct ieee80211_vht_mcs_info` u8 array with \
                size {NL80211_BAND_VHT_MCS_INFO_LEN}, but got length {}",
                buf.len()
            )
            .into());
        }

        Ok(Self {
            rx_mcs_map: u16::from_le_bytes([buf[0], buf[1]]),
            rx_highest: u16::from_le_bytes([buf[2], buf[3]]),
            tx_mcs_map: u16::from_le_bytes([buf[4], buf[5]]),
            tx_highest: u16::from_le_bytes([buf[6], buf[7]]),
        })
    }
}

const IEEE80211_VHT_CAP_MAX_MPDU_LENGTH_3895: u32 = 0x00000000;
const IEEE80211_VHT_CAP_MAX_MPDU_LENGTH_7991: u32 = 0x00000001;
const IEEE80211_VHT_CAP_MAX_MPDU_LENGTH_11454: u32 = 0x00000002;
const IEEE80211_VHT_CAP_MAX_MPDU_MASK: u32 = 0x00000003;
const IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_160MHZ: u32 = 0x00000004;
const IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_160_80PLUS80MHZ: u32 = 0x00000008;
const IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_MASK: u32 = 0x0000000C;
const IEEE80211_VHT_CAP_RXLDPC: u32 = 0x00000010;
const IEEE80211_VHT_CAP_SHORT_GI_80: u32 = 0x00000020;
const IEEE80211_VHT_CAP_SHORT_GI_160: u32 = 0x00000040;
const IEEE80211_VHT_CAP_TXSTBC: u32 = 0x00000080;
const IEEE80211_VHT_CAP_RXSTBC_1: u32 = 0x00000100;
const IEEE80211_VHT_CAP_RXSTBC_2: u32 = 0x00000200;
const IEEE80211_VHT_CAP_RXSTBC_3: u32 = 0x00000300;
const IEEE80211_VHT_CAP_RXSTBC_4: u32 = 0x00000400;
const IEEE80211_VHT_CAP_RXSTBC_MASK: u32 = 0x00000700;
const IEEE80211_VHT_CAP_SU_BEAMFORMER_CAPABLE: u32 = 0x00000800;
const IEEE80211_VHT_CAP_SU_BEAMFORMEE_CAPABLE: u32 = 0x00001000;
const IEEE80211_VHT_CAP_BEAMFORMEE_STS_SHIFT: u32 = 13;
const IEEE80211_VHT_CAP_BEAMFORMEE_STS_MASK: u32 =
    7 << IEEE80211_VHT_CAP_BEAMFORMEE_STS_SHIFT;
const IEEE80211_VHT_CAP_SOUNDING_DIMENSIONS_SHIFT: u32 = 16;
const IEEE80211_VHT_CAP_SOUNDING_DIMENSIONS_MASK: u32 =
    7 << IEEE80211_VHT_CAP_SOUNDING_DIMENSIONS_SHIFT;
const IEEE80211_VHT_CAP_MU_BEAMFORMER_CAPABLE: u32 = 0x00080000;
const IEEE80211_VHT_CAP_MU_BEAMFORMEE_CAPABLE: u32 = 0x00100000;
const IEEE80211_VHT_CAP_VHT_TXOP_PS: u32 = 0x00200000;
const IEEE80211_VHT_CAP_HTC_VHT: u32 = 0x00400000;
const IEEE80211_VHT_CAP_MAX_A_MPDU_LENGTH_EXPONENT_SHIFT: u32 = 23;
const IEEE80211_VHT_CAP_MAX_A_MPDU_LENGTH_EXPONENT_MASK: u32 =
    7 << IEEE80211_VHT_CAP_MAX_A_MPDU_LENGTH_EXPONENT_SHIFT;
const IEEE80211_VHT_CAP_VHT_LINK_ADAPTATION_VHT_UNSOL_MFB: u32 = 0x08000000;
const IEEE80211_VHT_CAP_VHT_LINK_ADAPTATION_VHT_MRQ_MFB: u32 = 0x0c000000;
const IEEE80211_VHT_CAP_RX_ANTENNA_PATTERN: u32 = 0x10000000;
const IEEE80211_VHT_CAP_TX_ANTENNA_PATTERN: u32 = 0x20000000;
const IEEE80211_VHT_CAP_EXT_NSS_BW_MASK: u32 = 0xc0000000;

bitflags::bitflags! {
    #[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
    #[non_exhaustive]
    pub struct Nl80211VhtCapInfo: u32 {
        const MaxMpduLength3895 = IEEE80211_VHT_CAP_MAX_MPDU_LENGTH_3895;
        const MaxMpduLength7991 = IEEE80211_VHT_CAP_MAX_MPDU_LENGTH_7991;
        const MaxMpduLength11454 = IEEE80211_VHT_CAP_MAX_MPDU_LENGTH_11454;
        const MaxMpduMask = IEEE80211_VHT_CAP_MAX_MPDU_MASK;
        const SuppChanWidth160mhz = IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_160MHZ;
        const SuppChanWidth160With80plus80mhz =
            IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_160_80PLUS80MHZ;
        const SuppChanWidthMask = IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_MASK;
        const Rxldpc = IEEE80211_VHT_CAP_RXLDPC;
        const ShortGi80 = IEEE80211_VHT_CAP_SHORT_GI_80;
        const ShortGi160 = IEEE80211_VHT_CAP_SHORT_GI_160;
        const TxStbc = IEEE80211_VHT_CAP_TXSTBC;
        const Rxstbc1 = IEEE80211_VHT_CAP_RXSTBC_1;
        const Rxstbc2 = IEEE80211_VHT_CAP_RXSTBC_2;
        const Rxstbc3 = IEEE80211_VHT_CAP_RXSTBC_3;
        const Rxstbc4 = IEEE80211_VHT_CAP_RXSTBC_4;
        const RxstbcMask = IEEE80211_VHT_CAP_RXSTBC_MASK;
        const SuBeamformerCapable = IEEE80211_VHT_CAP_SU_BEAMFORMER_CAPABLE;
        const SuBeamformeeCapable = IEEE80211_VHT_CAP_SU_BEAMFORMEE_CAPABLE;
        const BeamformeeStsMask = IEEE80211_VHT_CAP_BEAMFORMEE_STS_MASK;
        const SoundingDimensionsMask = IEEE80211_VHT_CAP_SOUNDING_DIMENSIONS_MASK;
        const MuBeamformerCapable = IEEE80211_VHT_CAP_MU_BEAMFORMER_CAPABLE;
        const MuBeamformeeCapable = IEEE80211_VHT_CAP_MU_BEAMFORMEE_CAPABLE;
        const VhtTxopPs = IEEE80211_VHT_CAP_VHT_TXOP_PS;
        const HtcVht = IEEE80211_VHT_CAP_HTC_VHT;
        const MaxAMpduLengthExponentMask =
            IEEE80211_VHT_CAP_MAX_A_MPDU_LENGTH_EXPONENT_MASK;
        const VhtLinkAdaptationVhtUnsolMfb =
            IEEE80211_VHT_CAP_VHT_LINK_ADAPTATION_VHT_UNSOL_MFB;
        const VhtLinkAdaptationVhtMrqMfb =
            IEEE80211_VHT_CAP_VHT_LINK_ADAPTATION_VHT_MRQ_MFB;
        const RxAntennaPattern = IEEE80211_VHT_CAP_RX_ANTENNA_PATTERN;
        const TxAntennaPattern = IEEE80211_VHT_CAP_TX_ANTENNA_PATTERN;
        const ExtNssBwMask = IEEE80211_VHT_CAP_EXT_NSS_BW_MASK;
        const _ = !0;
    }
}

impl<T: AsRef<[u8]> + ?Sized> Parseable<T> for Nl80211VhtCapInfo {
    fn parse(buf: &T) -> Result<Self, DecodeError> {
        let buf: &[u8] = buf.as_ref();
        Ok(Self::from_bits_retain(parse_u32(buf).context(format!(
            "Invalid Nl80211VhtCapInfo payload {buf:?}"
        ))?))
    }
}

impl Nl80211VhtCapInfo {
    pub const LENGTH: usize = 4;
}

impl Emitable for Nl80211VhtCapInfo {
    fn buffer_len(&self) -> usize {
        Self::LENGTH
    }

    fn emit(&self, buffer: &mut [u8]) {
        buffer.copy_from_slice(&self.bits().to_ne_bytes())
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Nl80211VhtCapability {
    pub cap_info: Nl80211VhtCapInfo,
    pub mcs_info: Nl80211VhtMcsInfo,
}

// TODO: Please add getter and setter function according to
//       802.11ac-2013 section '8.4.2.160 VHT Capabilities element'
impl Nl80211VhtCapability {
    pub const LENGTH: usize = 12;
}

impl Emitable for Nl80211VhtCapability {
    fn buffer_len(&self) -> usize {
        Self::LENGTH
    }

    fn emit(&self, buffer: &mut [u8]) {
        if buffer.len() < Self::LENGTH {
            log::error!(
                "Buffer size {} is smaller than desired size {}",
                buffer.len(),
                Self::LENGTH,
            );
            return;
        }
        self.cap_info.emit(&mut buffer[..Nl80211VhtCapInfo::LENGTH]);
        self.mcs_info.emit(&mut buffer[Nl80211VhtCapInfo::LENGTH..]);
    }
}

impl<T: AsRef<[u8]> + ?Sized> Parseable<T> for Nl80211VhtCapability {
    fn parse(buf: &T) -> Result<Self, DecodeError> {
        let buf: &[u8] = buf.as_ref();
        if buf.len() < Self::LENGTH {
            Err(format!(
                "Invalid length of payload for Nl80211VhtCapability, \
                expecting {}, but got {}",
                Self::LENGTH,
                buf.len()
            )
            .into())
        } else {
            Ok(Self {
                cap_info: Nl80211VhtCapInfo::parse(
                    &buf[..Nl80211VhtCapInfo::LENGTH],
                )?,
                mcs_info: Nl80211VhtMcsInfo::parse(
                    &buf[Nl80211VhtCapInfo::LENGTH..],
                )?,
            })
        }
    }
}
