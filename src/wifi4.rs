// SPDX-License-Identifier: MIT

// Hold WIFI 4(802.11n) specific data types

use netlink_packet_utils::{DecodeError, Emitable, Parseable};

use crate::bytes::write_u16_le;

const NL80211_CHAN_NO_HT: u32 = 0;
const NL80211_CHAN_HT20: u32 = 1;
const NL80211_CHAN_HT40MINUS: u32 = 2;
const NL80211_CHAN_HT40PLUS: u32 = 3;

// kernel data type: `enum nl80211_channel_type`
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum Nl80211HtWiphyChannelType {
    NoHt,
    Ht20,
    Ht40Minus,
    Ht40Plus,
    Other(u32),
}

impl From<u32> for Nl80211HtWiphyChannelType {
    fn from(d: u32) -> Self {
        match d {
            NL80211_CHAN_NO_HT => Self::NoHt,
            NL80211_CHAN_HT20 => Self::Ht20,
            NL80211_CHAN_HT40MINUS => Self::Ht40Minus,
            NL80211_CHAN_HT40PLUS => Self::Ht40Plus,
            _ => Self::Other(d),
        }
    }
}

impl From<Nl80211HtWiphyChannelType> for u32 {
    fn from(v: Nl80211HtWiphyChannelType) -> u32 {
        match v {
            Nl80211HtWiphyChannelType::NoHt => NL80211_CHAN_NO_HT,
            Nl80211HtWiphyChannelType::Ht20 => NL80211_CHAN_HT20,
            Nl80211HtWiphyChannelType::Ht40Minus => NL80211_CHAN_HT40MINUS,
            Nl80211HtWiphyChannelType::Ht40Plus => NL80211_CHAN_HT40PLUS,
            Nl80211HtWiphyChannelType::Other(d) => d,
        }
    }
}

const IEEE80211_HT_CAP_LDPC_CODING: u16 = 0x0001;
const IEEE80211_HT_CAP_SUP_WIDTH_20_40: u16 = 0x0002;
const IEEE80211_HT_CAP_SM_PS: u16 = 0x000C;
const IEEE80211_HT_CAP_GRN_FLD: u16 = 0x0010;
const IEEE80211_HT_CAP_SGI_20: u16 = 0x0020;
const IEEE80211_HT_CAP_SGI_40: u16 = 0x0040;
const IEEE80211_HT_CAP_TX_STBC: u16 = 0x0080;
const IEEE80211_HT_CAP_RX_STBC: u16 = 0x0300;
const IEEE80211_HT_CAP_DELAY_BA: u16 = 0x0400;
const IEEE80211_HT_CAP_MAX_AMSDU: u16 = 0x0800;
const IEEE80211_HT_CAP_DSSSCCK40: u16 = 0x1000;
const IEEE80211_HT_CAP_40MHZ_INTOLERANT: u16 = 0x4000;
const IEEE80211_HT_CAP_LSIG_TXOP_PROT: u16 = 0x8000;

// For linux kernel `struct  ieee80211_ht_cap.cap_info`
bitflags::bitflags! {
    #[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
    #[non_exhaustive]
    pub struct Nl80211HtCaps: u16 {
        const LdpcCoding = IEEE80211_HT_CAP_LDPC_CODING;
        const SupWidth2040 = IEEE80211_HT_CAP_SUP_WIDTH_20_40;
        const SmPs = IEEE80211_HT_CAP_SM_PS;
        const GrnFld = IEEE80211_HT_CAP_GRN_FLD;
        const Sgi20 = IEEE80211_HT_CAP_SGI_20;
        const Sgi40 = IEEE80211_HT_CAP_SGI_40;
        const TxStbc = IEEE80211_HT_CAP_TX_STBC;
        const RxStbc = IEEE80211_HT_CAP_RX_STBC;
        const DelayBa = IEEE80211_HT_CAP_DELAY_BA;
        const MaxAmsdu = IEEE80211_HT_CAP_MAX_AMSDU;
        const Dssscck40 = IEEE80211_HT_CAP_DSSSCCK40;
        const Intolerant40Mhz = IEEE80211_HT_CAP_40MHZ_INTOLERANT;
        const LsigTxopProt = IEEE80211_HT_CAP_LSIG_TXOP_PROT;
        const _ = !0;
    }
}

const IEEE80211_HT_MCS_MASK_LEN: usize = 10;
const NL80211_BAND_MCS_INFO_LEN: usize = 16;

// kernel data type: `struct ieee80211_mcs_info`
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Nl80211HtMcsInfo {
    pub rx_mask: [u8; IEEE80211_HT_MCS_MASK_LEN],
    pub rx_highest: u16,
    pub tx_params: u8,
}

impl Emitable for Nl80211HtMcsInfo {
    fn buffer_len(&self) -> usize {
        Self::LENGTH
    }

    fn emit(&self, buffer: &mut [u8]) {
        if buffer.len() < NL80211_BAND_MCS_INFO_LEN {
            log::error!(
                "Buffer size is smaller than NL80211_BAND_MCS_INFO_LEN \
                {NL80211_BAND_MCS_INFO_LEN}"
            );
            return;
        }
        buffer.iter_mut().for_each(|m| *m = 0);
        buffer[..IEEE80211_HT_MCS_MASK_LEN].copy_from_slice(&self.rx_mask);
        write_u16_le(
            &mut buffer
                [IEEE80211_HT_MCS_MASK_LEN..IEEE80211_HT_MCS_MASK_LEN + 2],
            self.rx_highest,
        );
        buffer[IEEE80211_HT_MCS_MASK_LEN + 2] = self.tx_params;
    }
}

impl Nl80211HtMcsInfo {
    // `struct ieee80211_mcs_info`.
    // Kernel document confirmed this is 16 bytes
    pub const LENGTH: usize = NL80211_BAND_MCS_INFO_LEN;
}

impl<T: AsRef<[u8]> + ?Sized> Parseable<T> for Nl80211HtMcsInfo {
    fn parse(buf: &T) -> Result<Self, DecodeError> {
        let buf: &[u8] = buf.as_ref();
        if buf.len() < NL80211_BAND_MCS_INFO_LEN {
            return Err(format!(
                "Expecting `struct ieee80211_ht_mcs_info` u8 array with \
                    size {NL80211_BAND_MCS_INFO_LEN}, but got length {}",
                buf.len()
            )
            .into());
        }
        let mut rx_mask = [0u8; IEEE80211_HT_MCS_MASK_LEN];
        rx_mask.copy_from_slice(&buf[..IEEE80211_HT_MCS_MASK_LEN]);

        Ok(Self {
            rx_mask,
            rx_highest: u16::from_le_bytes([
                buf[IEEE80211_HT_MCS_MASK_LEN],
                buf[IEEE80211_HT_MCS_MASK_LEN + 1],
            ]),
            tx_params: buf[IEEE80211_HT_MCS_MASK_LEN + 2],
        })
    }
}

const NL80211_HT_CAPABILITY_LEN: usize = 26;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Nl80211HtCapabilityMask(pub [u8; NL80211_HT_CAPABILITY_LEN]);

impl Nl80211HtCapabilityMask {
    pub const LENGTH: usize = NL80211_HT_CAPABILITY_LEN;

    pub fn new(value: &[u8]) -> Self {
        let mut data = [0u8; Self::LENGTH];
        if value.len() > Self::LENGTH {
            data.copy_from_slice(&value[..Self::LENGTH]);
        } else {
            data[..value.len()].copy_from_slice(value)
        }
        Self(data)
    }
}

impl Emitable for Nl80211HtCapabilityMask {
    fn buffer_len(&self) -> usize {
        Self::LENGTH
    }

    fn emit(&self, buffer: &mut [u8]) {
        if buffer.len() < Self::LENGTH {
            log::error!(
                "Nl80211HtCapabilityMask buffer size is smaller than \
                required size {}",
                Self::LENGTH
            );
            return;
        }
        buffer[..Self::LENGTH].copy_from_slice(&self.0)
    }
}
