// SPDX-License-Identifier: MIT

// Hold WIFI 4(802.11n) specific data types

use anyhow::Context;
use netlink_packet_utils::{
    parsers::{parse_u16, parse_u32, parse_u8},
    DecodeError, Emitable, Parseable,
};

use crate::bytes::{get_bit, get_bits_as_u8, write_u16_le};

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

const IEEE80211_HT_CAP_LDPC_CODING: u16 = 1;
const IEEE80211_HT_CAP_SUP_WIDTH_20_40: u16 = 1 << 1;
const IEEE80211_HT_CAP_SM_PS_DYNAMIC: u16 = 1 << 2;
const IEEE80211_HT_CAP_SM_PS_RESERVE: u16 = 1 << 3;
const IEEE80211_HT_CAP_GRN_FLD: u16 = 1 << 4;
const IEEE80211_HT_CAP_SGI_20: u16 = 1 << 5;
const IEEE80211_HT_CAP_SGI_40: u16 = 1 << 6;
const IEEE80211_HT_CAP_TX_STBC: u16 = 1 << 7;
const IEEE80211_HT_CAP_RX_STBC1: u16 = 1 << 8;
const IEEE80211_HT_CAP_RX_STBC2: u16 = 1 << 9;
const IEEE80211_HT_CAP_DELAY_BA: u16 = 1 << 10;
const IEEE80211_HT_CAP_MAX_AMSDU: u16 = 1 << 11;
const IEEE80211_HT_CAP_DSSSCCK40: u16 = 0x1000;
const IEEE80211_HT_CAP_40MHZ_INTOLERANT: u16 = 0x4000;
const IEEE80211_HT_CAP_LSIG_TXOP_PROT: u16 = 0x8000;

// For linux kernel `struct  ieee80211_ht_cap.cap_info`
bitflags::bitflags! {
    #[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
    #[non_exhaustive]
    pub struct Nl80211HtCaps: u16 {
        /// ndicates support for receiving LDPC coded packets
        const LdpcCoding = IEEE80211_HT_CAP_LDPC_CODING;
        /// Both 20 MHz and 40 MHz operation are supported
        const SupWidth2040 = IEEE80211_HT_CAP_SUP_WIDTH_20_40;
        /// Dynamic SM power save mode
        const SmPsDynamic = IEEE80211_HT_CAP_SM_PS_DYNAMIC;
        /// When both `SmPsDynamic` and `SmPsReserve` are set, it means
        /// SM power save mode is disabled
        /// When neither `SmPsDynamic` or `SmPsReserve` is set, it means
        /// static SM power save mode.
        const SmPsReserve = IEEE80211_HT_CAP_SM_PS_RESERVE;
        /// Indicates support for the reception of PPDUs with HT-greenfield
        /// format
        const HtGreenfield = IEEE80211_HT_CAP_GRN_FLD;
        /// Short GI for 20 MHz
        const Sgi20 = IEEE80211_HT_CAP_SGI_20;
        /// Short GI for 40 MHz
        const Sgi40 = IEEE80211_HT_CAP_SGI_40;
        const TxStbc = IEEE80211_HT_CAP_TX_STBC;
        /// When both `RxStbc1` and `RxStbc2` are set, it means support of one,
        /// two and three spatial streams
        const RxStbc1 = IEEE80211_HT_CAP_RX_STBC1;
        const RxStbc2 = IEEE80211_HT_CAP_RX_STBC2;
        /// HT-Delayed Block Ack
        const HtDelayBlockAck = IEEE80211_HT_CAP_DELAY_BA;
        /// When set, A-MSDU Length is 7935 bytes, unset is 3839 bytes.
        const MaxAmsdu7935 = IEEE80211_HT_CAP_MAX_AMSDU;
        /// DSSS/CCK Mode in 40 MHz
        const Dssscck40 = IEEE80211_HT_CAP_DSSSCCK40;
        /// Forty MHz Intolerant
        const Intolerant40Mhz = IEEE80211_HT_CAP_40MHZ_INTOLERANT;
        /// L-SIG TXOP Protection Support
        const LsigTxopProt = IEEE80211_HT_CAP_LSIG_TXOP_PROT;
        const _ = !0;
    }
}

impl Nl80211HtCaps {
    pub const LENGTH: usize = 2;

    pub fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self::from_bits_retain(
            parse_u16(buf).context(format!("Invalid Nl80211HtCaps {buf:?}"))?,
        ))
    }
}

impl Emitable for Nl80211HtCaps {
    fn buffer_len(&self) -> usize {
        Self::LENGTH
    }

    fn emit(&self, buffer: &mut [u8]) {
        buffer[0..self.buffer_len()].copy_from_slice(&self.bits().to_ne_bytes())
    }
}

const IEEE80211_HT_MCS_MASK_LEN: usize = 10;
const NL80211_BAND_MCS_INFO_LEN: usize = 16;

// kernel data type: `struct ieee80211_mcs_info`
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Nl80211HtMcsInfo {
    pub rx_mask: [u8; IEEE80211_HT_MCS_MASK_LEN],
    /// The Rx Highest Supported Data Rate in Mb/s. The 0 means STA does not
    /// specific highest data rate it can receive.
    pub rx_highest: u16,
    pub tx_params: Nl80211HtTxParameter,
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
        buffer[IEEE80211_HT_MCS_MASK_LEN + 2] = self.tx_params.into();
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
            tx_params: buf[IEEE80211_HT_MCS_MASK_LEN + 2].into(),
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

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Nl80211ElementHtCap {
    /// HT Capabilities Info
    pub caps: Nl80211HtCaps,
    /// A-MPDU Parameters
    pub a_mpdu_para: Nl80211HtAMpduPara,
    /// Supported MCS Set
    pub mcs_set: Nl80211HtMcsInfo,
    /// HT Extended Capabilities
    pub ht_ext_cap: Nl80211HtExtendedCap,
    /// Transmit Beamforming Capabilities
    pub transmit_beamforming_cap: Nl80211HtTransmitBeamformingCaps,
    /// ASEL Capabilities
    pub asel_cap: Nl80211HtAselCaps,
}

impl Nl80211ElementHtCap {
    // Hard coded to 26 by IEEE 802.11n-2009
    pub const LENGTH: usize = 26;

    pub fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        if buf.len() < Self::LENGTH {
            return Err(format!(
                "Nl80211ElementHtCap buffer size is smaller than \
                required size {}: {buf:?}",
                Self::LENGTH
            )
            .into());
        }
        let mut offset = 0usize;
        let caps = Nl80211HtCaps::parse(&buf[..Nl80211HtCaps::LENGTH])?;
        offset += Nl80211HtCaps::LENGTH;

        let a_mpdu_para = Nl80211HtAMpduPara::parse(
            &buf[offset..offset + Nl80211HtAMpduPara::LENGTH],
        )?;
        offset += Nl80211HtAMpduPara::LENGTH;

        let mcs_set = Nl80211HtMcsInfo::parse(
            &buf[offset..offset + Nl80211HtMcsInfo::LENGTH],
        )?;
        offset += Nl80211HtMcsInfo::LENGTH;

        let ht_ext_cap = Nl80211HtExtendedCap::parse(
            &buf[offset..offset + Nl80211HtExtendedCap::LENGTH],
        )?;
        offset += Nl80211HtExtendedCap::LENGTH;

        let transmit_beamforming_cap = Nl80211HtTransmitBeamformingCaps::parse(
            &buf[offset..offset + Nl80211HtTransmitBeamformingCaps::LENGTH],
        )?;
        offset += Nl80211HtTransmitBeamformingCaps::LENGTH;
        let asel_cap = Nl80211HtAselCaps::parse(
            &buf[offset..offset + Nl80211HtAselCaps::LENGTH],
        )?;

        Ok(Self {
            caps,
            a_mpdu_para,
            mcs_set,
            ht_ext_cap,
            transmit_beamforming_cap,
            asel_cap,
        })
    }
}

impl Emitable for Nl80211ElementHtCap {
    fn buffer_len(&self) -> usize {
        Self::LENGTH
    }

    fn emit(&self, buffer: &mut [u8]) {
        if buffer.len() < Self::LENGTH {
            log::error!(
                "Nl80211ElementHtCap buffer size is smaller than \
                required size {}: {buffer:?}",
                Self::LENGTH
            );
            return;
        }
        let mut offset = 0;
        self.caps.emit(buffer);
        offset += self.caps.buffer_len();
        self.a_mpdu_para.emit(&mut buffer[offset..]);
        offset += self.a_mpdu_para.buffer_len();
        self.mcs_set.emit(&mut buffer[offset..]);
        offset += self.mcs_set.buffer_len();
        self.ht_ext_cap.emit(&mut buffer[offset..]);
        offset += self.ht_ext_cap.buffer_len();
        self.transmit_beamforming_cap.emit(&mut buffer[offset..]);
        offset += self.transmit_beamforming_cap.buffer_len();
        self.asel_cap.emit(&mut buffer[offset..]);
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Nl80211HtAMpduPara {
    /// The maximum length of A-MPDU that the STA can receive.
    /// The length equal to: 2 ** (13 + max_len_exponent) - 1
    pub max_len_exponent: u8,
    /// Minimum time between the start of adjacent MPDUs within an A- MPDU that
    /// the STA can receive:
    /// * Set to 0 for no restriction
    /// * Set to 1 for 1/4 μs
    /// * Set to 2 for 1/2 μs
    /// * Set to 3 for 1 μs
    /// * Set to 4 for 2 μs
    /// * Set to 5 for 4 μs
    /// * Set to 6 for 8 μs
    /// * Set to 7 for 16 μs
    pub min_space: u8,
}

impl From<u8> for Nl80211HtAMpduPara {
    fn from(d: u8) -> Self {
        Self {
            max_len_exponent: d & 0b11,
            min_space: (d & 0b11100) >> 2,
        }
    }
}

impl From<Nl80211HtAMpduPara> for u8 {
    fn from(v: Nl80211HtAMpduPara) -> u8 {
        v.max_len_exponent | v.min_space << 2
    }
}

impl Emitable for Nl80211HtAMpduPara {
    fn buffer_len(&self) -> usize {
        1
    }

    fn emit(&self, buffer: &mut [u8]) {
        buffer[0] = (*self).into()
    }
}

impl Nl80211HtAMpduPara {
    pub const LENGTH: usize = 1;

    pub fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        if buf.len() != Self::LENGTH {
            return Err(format!(
                "Invalid Nl80211HtAMpduPara , expected length {}, \
                but got {buf:?}",
                Self::LENGTH
            )
            .into());
        }
        Ok(Self::from(buf[0]))
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Nl80211HtTxParameter {
    pub mcs_set_defined: bool,
    pub tx_rx_mcs_set_not_equal: bool,
    pub max_spatial_streams: u8,
    pub unequal_modulation_supported: bool,
}

impl From<u8> for Nl80211HtTxParameter {
    fn from(d: u8) -> Self {
        let d: [u8; 1] = [d];
        Self {
            mcs_set_defined: get_bit(&d, 0),
            tx_rx_mcs_set_not_equal: get_bit(&d, 1),
            max_spatial_streams: get_bits_as_u8(&d, 2, 3),
            unequal_modulation_supported: get_bit(&d, 4),
        }
    }
}

impl From<Nl80211HtTxParameter> for u8 {
    fn from(v: Nl80211HtTxParameter) -> u8 {
        v.mcs_set_defined as u8
            | ((v.tx_rx_mcs_set_not_equal as u8) << 1)
            | (v.max_spatial_streams << 2)
            | ((v.unequal_modulation_supported as u8) << 4)
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Nl80211HtExtendedCap {
    pub pco: bool,
    pub pco_trans_time: u8,
    pub mcs_feedback: u8,
    pub support_ht_control: bool,
    pub rd_responder: bool,
}

impl Nl80211HtExtendedCap {
    pub const LENGTH: usize = 2;

    pub fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        if buf.len() != Self::LENGTH {
            return Err(format!(
                "Invalid Nl80211HtExtendedCap, expected length {}, \
                but got {buf:?}",
                Self::LENGTH
            )
            .into());
        }
        Ok(Self::from([buf[0], buf[1]]))
    }
}

impl Emitable for Nl80211HtExtendedCap {
    fn buffer_len(&self) -> usize {
        Self::LENGTH
    }

    fn emit(&self, buffer: &mut [u8]) {
        let data: [u8; 2] = (*self).into();
        buffer[0] = data[0];
        buffer[1] = data[1];
    }
}

impl From<[u8; 2]> for Nl80211HtExtendedCap {
    fn from(buf: [u8; 2]) -> Self {
        Self {
            pco: get_bit(&buf, 0),
            pco_trans_time: get_bits_as_u8(&buf, 1, 2),
            mcs_feedback: get_bits_as_u8(&buf, 8, 9),
            support_ht_control: get_bit(&buf, 10),
            rd_responder: get_bit(&buf, 11),
        }
    }
}

impl From<Nl80211HtExtendedCap> for [u8; 2] {
    fn from(v: Nl80211HtExtendedCap) -> [u8; 2] {
        [
            v.pco as u8 | (v.pco_trans_time << 1) | (v.mcs_feedback & 0b1) << 7,
            (v.mcs_feedback & 0b11)
                | ((v.support_ht_control as u8) << 2)
                | ((v.rd_responder as u8) << 3),
        ]
    }
}

bitflags::bitflags! {
    #[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
    #[non_exhaustive]
    pub struct Nl80211HtTransmitBeamformingCaps: u32 {
        /// Indicates this STA can receive Transmit Beamforming steered
        /// frames using implicit feedback
        const ImplicitReceiving= 1 << 0;
        /// Indicates this STA can receive staggered sounding frames.
        const ReceiveStaggeredSounding = 1 << 1;
        /// Indicates this STA can transmit staggered sounding frames.
        const TransmitStaggeredSounding = 1 << 2;
        /// Indicates this receiver can interpret null data packets as
        /// sounding frames.
        const ReceiveNdp = 1 << 3;
        /// Indicates this STA can transmit null data packets as
        /// sounding frames.
        const TransmitNdp = 1 << 4;
        /// Indicates this STA can apply implicit transmit beamforming.
        const ImplicitTransmit = 1 << 5;
        /// The STA can respond to a calibration request using the CSI report
        const CalibrationCanRespon = 1 << 6;
        /// The STA can initiate a calibration request.
        const CalibrationCanInitiate = 1 << 7;
        /// Indicates this STA can apply transmit beamforming using CSI
        /// explicit feedback in its transmission
        const ExplicitCsiTransmit = 1 << 8;
        /// Indicates this STA can apply transmit beamforming using
        /// noncompressed beamforming feedback matrix explicit feedback in its
        /// transmission
        const ExplicitNoncompressedSteering = 1 << 9;
        /// Indicates this STA can apply transmit beamforming using
        /// compressed beamforming feedback matrix explicit feedback in its
        /// transmission
        const ExplicitCompressedSteering = 1 << 10;
        /// Indicates this receiver can return delayed CSI explicit feedback.
        const ExplicitTransmitCsiFeedbackDelay = 1 << 11;
        /// Indicates this receiver can return immediate CSI explicit feedback.
        const ExplicitTransmitCsiFeedbackImmediate = 1 << 12;
        /// Indicates this receiver can return delayed noncompressed
        /// beamforming feedback matrix explicit feedback
        const ExplicitNoncompressedFeebackDelay = 1 << 13;
        /// Indicates this receiver can return immediate noncompressed
        /// beamforming feedback matrix explicit feedback
        const ExplicitNoncompressedFeebackImmediate = 1 << 14;
        /// Indicates this receiver can return delayed compressed
        /// beamforming feedback matrix explicit feedback
        const ExplicitCompressedFeebackDelay = 1 << 15;
        /// Indicates this receiver can return immediate compressed
        /// beamforming feedback matrix explicit feedback
        const ExplicitCompressedFeebackImmediate = 1 << 16;
        /// Support 2 minimal groups used for explicit feedback report
        /// Unset means 1 minimal grouping.
        const MinimalGrouping2 = 1 << 17;
        /// Support 4 minimal groups used for explicit feedback report
        /// Unset means 1 minimal grouping.
        const MinimalGrouping4 = 1 << 18;
        /// Support 2 Tx beamformer antennas when CSI feedback is required.
        /// When both `CsiAntennas2Tx` and `CsiAntennas3Tx` unset, it means
        /// single Tx antenna sounding.
        /// When both `CsiAntennas2Tx` and `CsiAntennas3Tx` set, it means 4 Tx
        /// antenna sounding.
        const CsiBeamformerAntennas2Tx = 1 << 19;
        /// Support 3 Tx beamformer antennas when CSI feedback is required.
        /// When both `CsiAntennas2Tx` and `CsiAntennas3Tx` unset, it means
        /// single Tx antenna sounding.
        /// When both `CsiAntennas2Tx` and `CsiAntennas3Tx` set, it means 4 Tx
        /// antenna sounding.
        const CsiAntennas3Tx = 1 << 20;
        /// Support 2 Tx beamformer antennas when noncompressed beamforming
        /// feedback matrix is required.
        /// When both `UncompressedSteeringAntennas2Tx` and
        /// `UncompressedSteeringAntennas3Tx` set, it means 4 Tx antennas
        /// sounding.
        /// When both `UncompressedSteeringAntennas2Tx` and
        /// `UncompressedSteeringAntennas3Tx` unset, it means single Tx antenna
        /// sounding.
        const UncompressedSteeringAntennas2Tx = 1 << 21;
        /// Support 3 Tx beamformer antennas when noncompressed beamforming
        /// feedback matrix is required.
        /// When both `UncompressedSteeringAntennas2Tx` and
        /// `UncompressedSteeringAntennas3Tx` set, it means 4 Tx antennas
        /// sounding.
        /// When both `UncompressedSteeringAntennas2Tx` and
        /// `UncompressedSteeringAntennas3Tx` unset, it means single Tx antenna
        /// sounding.
        const UncompressedSteeringAntennas3Tx = 1 << 22;
        /// Support 2 Tx beamformer antennas when compressed beamforming
        /// feedback matrix is required.
        /// When both `UncompressedSteeringAntennas2Tx` and
        /// `UncompressedSteeringAntennas3Tx` set, it means 4 Tx antennas
        /// sounding.
        /// When both `UncompressedSteeringAntennas2Tx` and
        /// `UncompressedSteeringAntennas3Tx` unset, it means single Tx antenna
        /// sounding.
        const CompressedSteeringAntennas2Tx = 1 << 23;
        /// Support 3 Tx beamformer antennas when compressed beamforming
        /// feedback matrix is required.
        /// When both `UncompressedSteeringAntennas2Tx` and
        /// `UncompressedSteeringAntennas3Tx` set, it means 4 Tx antennas
        /// sounding.
        /// When both `UncompressedSteeringAntennas2Tx` and
        /// `UncompressedSteeringAntennas3Tx` unset, it means single Tx antenna
        /// sounding.
        const CompressedSteeringAntennas3Tx = 1 << 24;
        /// Support 2 rows of CSI when CSI feedback is required
        /// When both `CsiRows2` and `CsiRows3` set, it means 4 rows of CSI.
        /// When both `CsiRows2` and `CsiRows3` unset, it means 1 row of CSI.
        const CsiRows2 = 1 << 25;
        /// Support 3 rows of CSI when CSI feedback is required
        /// When both `CsiRows2` and `CsiRows3` set, it means 4 rows of CSI.
        /// When both `CsiRows2` and `CsiRows3` unset, it means 1 row of CSI.
        const CsiRows3 = 1 << 26;
        /// Support 2 space-time streams(columns of the MIMO channel matrix)
        /// for which channel dimensions can be simultaneously estimated when
        /// receiving an NDP sounding PPDU or the extension portion of the HT
        /// Long Training fields(HT-LTFs) in a staggered sounding PPDU.
        /// When both `SpaceTimeStream2` and `SpaceTimeStream3` set, it means
        /// 4 space-time streams.
        /// When both `SpaceTimeStream2` and `SpaceTimeStream3` unset, it means
        /// 1 space-time stream.
        const SpaceTimeStream2 = 1 << 27;
        /// Support 3 space-time streams(columns of the MIMO channel matrix)
        /// for which channel dimensions can be simultaneously estimated when
        /// receiving an NDP sounding PPDU or the extension portion of the HT
        /// Long Training fields(HT-LTFs) in a staggered sounding PPDU.
        /// When both `SpaceTimeStream2` and `SpaceTimeStream3` set, it means
        /// 4 space-time streams.
        /// When both `SpaceTimeStream2` and `SpaceTimeStream3` unset, it means
        /// 1 space-time stream.
        const SpaceTimeStream3 = 1 << 28;
        const _ = !0;
    }
}

impl Nl80211HtTransmitBeamformingCaps {
    pub const LENGTH: usize = 4;

    pub fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self::from_bits_retain(parse_u32(buf).context(format!(
            "Invalid Nl80211HtTransmitBeamformingCaps {buf:?}"
        ))?))
    }
}

impl Emitable for Nl80211HtTransmitBeamformingCaps {
    fn buffer_len(&self) -> usize {
        Self::LENGTH
    }

    fn emit(&self, buffer: &mut [u8]) {
        buffer[0..self.buffer_len()].copy_from_slice(&self.bits().to_ne_bytes())
    }
}

bitflags::bitflags! {
    #[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
    #[non_exhaustive]
    pub struct Nl80211HtAselCaps : u8 {
        /// Indicates this STA supports ASEL
        const AntennaSelection = 1 << 0;
        /// Indicates this STA supports transmit ASEL based on explicit
        /// CSI feedback
        const BasedOnExplicitCsiFeedback = 1 << 1;
        /// Indicates this STA supports transmit ASEL based on antenna
        /// indices feedback
        const BasedOnAntennaIndicesFeedback = 1 << 2;
        /// Indicates this STA can compute CSI and provide CSI feedback
        /// in support of ASEL
        const ExplicitCsiFeedback = 1 << 3;
        /// Indicates this STA can compute an antenna indices selection
        /// and return an antenna indices selection in support of ASEL
        const AntennaIndicesFeedback = 1 << 4;
        /// Indicates this STA supports receive ASEL
        const ReceiveAsel =  1 << 5;
        /// Indicates whether this STA can transmit sounding PPDUs for ASEL
        /// training on request
        const TransmitSoundingPpdu = 1 << 6;
        const _ = !0;
    }
}

impl Nl80211HtAselCaps {
    pub const LENGTH: usize = 1;

    pub fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self::from_bits_retain(
            parse_u8(buf)
                .context(format!("Invalid Nl80211HtAselCaps {buf:?}"))?,
        ))
    }
}

impl Emitable for Nl80211HtAselCaps {
    fn buffer_len(&self) -> usize {
        Self::LENGTH
    }

    fn emit(&self, buffer: &mut [u8]) {
        buffer[0..self.buffer_len()].copy_from_slice(&self.bits().to_ne_bytes())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::macros::test::{roundtrip_emit_parse_test, roundtrip_from_test};

    roundtrip_emit_parse_test!(caps, Nl80211HtCaps, Nl80211HtCaps::all());
    roundtrip_emit_parse_test!(
        asel_caps,
        Nl80211HtAselCaps,
        Nl80211HtAselCaps::all()
    );
    roundtrip_emit_parse_test!(
        transmit_beamforming_cap,
        Nl80211HtTransmitBeamformingCaps,
        Nl80211HtTransmitBeamformingCaps::all(),
    );

    roundtrip_from_test!(tx_params, Nl80211HtTxParameter => u8, Nl80211HtTxParameter {
        mcs_set_defined: false,
        tx_rx_mcs_set_not_equal: false,
        max_spatial_streams: 1,
        unequal_modulation_supported: false,
    });

    roundtrip_from_test!(ht_wiphy_no_ht, Nl80211HtWiphyChannelType => u32, Nl80211HtWiphyChannelType::NoHt);
    roundtrip_from_test!(ht_wiphy_ht_20, Nl80211HtWiphyChannelType => u32, Nl80211HtWiphyChannelType::Ht20);
    roundtrip_from_test!(ht_wiphy_other, Nl80211HtWiphyChannelType => u32, Nl80211HtWiphyChannelType::Other(NL80211_CHAN_HT40PLUS + 1));

    roundtrip_emit_parse_test!(
        mcs_info,
        Nl80211HtMcsInfo,
        Nl80211HtMcsInfo {
            rx_mask: [0xA5; IEEE80211_HT_MCS_MASK_LEN],
            rx_highest: u16::MAX,
            tx_params: Nl80211HtTxParameter {
                mcs_set_defined: false,
                tx_rx_mcs_set_not_equal: false,
                max_spatial_streams: 1,
                unequal_modulation_supported: false,
            },
        },
    );

    roundtrip_from_test!(a_mpdu_para, Nl80211HtAMpduPara => u8, Nl80211HtAMpduPara {
        max_len_exponent: u8::MAX & 0b11,
        min_space: u8::MAX & 0b111,
    });

    roundtrip_from_test!(extend_cap, Nl80211HtExtendedCap => [u8; 2], Nl80211HtExtendedCap {
        pco: true,
        pco_trans_time: 1,
        mcs_feedback: 1,
        support_ht_control: true,
        rd_responder: true,
    });

    roundtrip_emit_parse_test!(
        cap_mask,
        Nl80211ElementHtCap,
        Nl80211ElementHtCap {
            caps: Nl80211HtCaps::all(),
            a_mpdu_para: Nl80211HtAMpduPara {
                max_len_exponent: 3,
                min_space: 7,
            },
            mcs_set: Nl80211HtMcsInfo {
                rx_mask: [0xA5; IEEE80211_HT_MCS_MASK_LEN],
                rx_highest: u16::MAX,
                tx_params: Nl80211HtTxParameter {
                    mcs_set_defined: false,
                    tx_rx_mcs_set_not_equal: false,
                    max_spatial_streams: 1,
                    unequal_modulation_supported: false,
                },
            },
            ht_ext_cap: Nl80211HtExtendedCap {
                pco: true,
                pco_trans_time: 2,
                mcs_feedback: 2,
                support_ht_control: true,
                rd_responder: true,
            },
            transmit_beamforming_cap: Nl80211HtTransmitBeamformingCaps::all(),
            asel_cap: Nl80211HtAselCaps::all(),
        },
    );
}
