// SPDX-License-Identifier: MIT

use anyhow::Context;
use byteorder::{ByteOrder, NativeEndian};
use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer},
    parsers::{parse_u16, parse_u32, parse_u8},
    DecodeError, Emitable, Parseable,
};

pub const NL80211_RATE_INFO_BITRATE: u16 = 1;
pub const NL80211_RATE_INFO_MCS: u16 = 2;
pub const NL80211_RATE_INFO_40_MHZ_WIDTH: u16 = 3;
pub const NL80211_RATE_INFO_SHORT_GI: u16 = 4;
pub const NL80211_RATE_INFO_BITRATE32: u16 = 5;
pub const NL80211_RATE_INFO_VHT_MCS: u16 = 6;
pub const NL80211_RATE_INFO_VHT_NSS: u16 = 7;
pub const NL80211_RATE_INFO_80_MHZ_WIDTH: u16 = 8;
pub const NL80211_RATE_INFO_80P80_MHZ_WIDTH: u16 = 9;
pub const NL80211_RATE_INFO_160_MHZ_WIDTH: u16 = 10;
pub const NL80211_RATE_INFO_10_MHZ_WIDTH: u16 = 11;
pub const NL80211_RATE_INFO_5_MHZ_WIDTH: u16 = 12;
pub const NL80211_RATE_INFO_HE_MCS: u16 = 13;
pub const NL80211_RATE_INFO_HE_NSS: u16 = 14;
pub const NL80211_RATE_INFO_HE_GI: u16 = 15;
pub const NL80211_RATE_INFO_HE_DCM: u16 = 16;
pub const NL80211_RATE_INFO_HE_RU_ALLOC: u16 = 17;
pub const NL80211_RATE_INFO_320_MHZ_WIDTH: u16 = 18;
pub const NL80211_RATE_INFO_EHT_MCS: u16 = 19;
pub const NL80211_RATE_INFO_EHT_NSS: u16 = 20;
pub const NL80211_RATE_INFO_EHT_GI: u16 = 21;
pub const NL80211_RATE_INFO_EHT_RU_ALLOC: u16 = 22;
pub const NL80211_RATE_INFO_S1G_MCS: u16 = 23;
pub const NL80211_RATE_INFO_S1G_NSS: u16 = 24;
pub const NL80211_RATE_INFO_1_MHZ_WIDTH: u16 = 25;
pub const NL80211_RATE_INFO_2_MHZ_WIDTH: u16 = 26;
pub const NL80211_RATE_INFO_4_MHZ_WIDTH: u16 = 27;
pub const NL80211_RATE_INFO_8_MHZ_WIDTH: u16 = 28;
pub const NL80211_RATE_INFO_16_MHZ_WIDTH: u16 = 29;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Nl80211RateInfo {
    /// Total bitrate, 100kb/s
    Bitrate(u16),
    /// MCS index for 802.11n
    Mcs(u8),
    MhzWidth(u32),
    /// 400ns guard interval
    ShortGi,
    /// Total bitrate, 100kb/s
    Bitrate32(u32),
    /// MCS index for VHT
    VhtMcs(u8),
    /// Number of streams in VHT
    VhtNss(u8),
    /// Unused, 80+80 is treated the same as 160 for purposes of the bitrates
    MhzWidth80Plus80,
    /// HE MCS index
    HeMcs(u8),
    /// HE NSS value
    HeNss(u8),
    /// HE guard interval identifier [`Nl80211HeGi`]
    HeGi(Nl80211HeGi),
    /// HE DCM value
    HeDcm(u8),
    /// HE RU allocation, if not present then non-OFDMA was used.
    /// See [`Nl80211HeRuAllocation`]
    HeRuAlloc(Nl80211HeRuAllocation),
    /// S1G MCS index
    S1gMcs(u8),
    /// S1G NSS value
    S1gNss(u8),
    /// EHT MCS index
    EhtMcs(u8),
    /// EHT NSS value
    EhtNss(u8),
    /// EHT guard interval identifier [`Nl80211EhtGi`]
    EhtGi(Nl80211EhtGi),
    /// EHT RU allocation, if not present then non-OFDMA was used.
    /// See [`Nl80211EhtRuAllocation`]
    EhtRuAlloc(Nl80211EhtRuAllocation),

    Other(DefaultNla),
}

impl Nla for Nl80211RateInfo {
    fn value_len(&self) -> usize {
        match self {
            Self::MhzWidth(_) | Self::ShortGi | Self::MhzWidth80Plus80 => 0,
            Self::Mcs(_)
            | Self::VhtMcs(_)
            | Self::VhtNss(_)
            | Self::HeMcs(_)
            | Self::HeNss(_)
            | Self::HeGi(_)
            | Self::HeDcm(_)
            | Self::HeRuAlloc(_)
            | Self::S1gMcs(_)
            | Self::S1gNss(_)
            | Self::EhtMcs(_)
            | Self::EhtNss(_)
            | Self::EhtGi(_)
            | Self::EhtRuAlloc(_) => 1,
            Self::Bitrate(_) => 2,
            Self::Bitrate32(_) => 4,
            Self::Other(nlas) => nlas.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Bitrate(_) => NL80211_RATE_INFO_BITRATE,
            Self::Mcs(_) => NL80211_RATE_INFO_MCS,
            Self::MhzWidth(1) => NL80211_RATE_INFO_1_MHZ_WIDTH,
            Self::MhzWidth(2) => NL80211_RATE_INFO_2_MHZ_WIDTH,
            Self::MhzWidth(4) => NL80211_RATE_INFO_4_MHZ_WIDTH,
            Self::MhzWidth(5) => NL80211_RATE_INFO_5_MHZ_WIDTH,
            Self::MhzWidth(8) => NL80211_RATE_INFO_8_MHZ_WIDTH,
            Self::MhzWidth(10) => NL80211_RATE_INFO_10_MHZ_WIDTH,
            Self::MhzWidth(16) => NL80211_RATE_INFO_16_MHZ_WIDTH,
            Self::MhzWidth(40) => NL80211_RATE_INFO_40_MHZ_WIDTH,
            Self::MhzWidth(80) => NL80211_RATE_INFO_80_MHZ_WIDTH,
            Self::MhzWidth(160) => NL80211_RATE_INFO_160_MHZ_WIDTH,
            Self::MhzWidth(320) => NL80211_RATE_INFO_320_MHZ_WIDTH,
            Self::MhzWidth(freq) => {
                log::warn!("Invalid Nl80211RateInfo::MhzWidth {freq:?}");
                u16::MAX
            }
            Self::MhzWidth80Plus80 => NL80211_RATE_INFO_80P80_MHZ_WIDTH,
            Self::ShortGi => NL80211_RATE_INFO_SHORT_GI,
            Self::Bitrate32(_) => NL80211_RATE_INFO_BITRATE32,
            Self::VhtMcs(_) => NL80211_RATE_INFO_VHT_MCS,
            Self::VhtNss(_) => NL80211_RATE_INFO_VHT_NSS,
            Self::HeMcs(_) => NL80211_RATE_INFO_HE_MCS,
            Self::HeNss(_) => NL80211_RATE_INFO_HE_NSS,
            Self::HeGi(_) => NL80211_RATE_INFO_HE_GI,
            Self::HeDcm(_) => NL80211_RATE_INFO_HE_DCM,
            Self::HeRuAlloc(_) => NL80211_RATE_INFO_HE_RU_ALLOC,
            Self::S1gMcs(_) => NL80211_RATE_INFO_S1G_MCS,
            Self::S1gNss(_) => NL80211_RATE_INFO_S1G_NSS,
            Self::EhtMcs(_) => NL80211_RATE_INFO_EHT_MCS,
            Self::EhtNss(_) => NL80211_RATE_INFO_EHT_NSS,
            Self::EhtGi(_) => NL80211_RATE_INFO_EHT_GI,
            Self::EhtRuAlloc(_) => NL80211_RATE_INFO_EHT_RU_ALLOC,
            Self::Other(info) => info.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Bitrate(bitrate) => NativeEndian::write_u16(buffer, *bitrate),
            Self::Mcs(d)
            | Self::VhtMcs(d)
            | Self::VhtNss(d)
            | Self::HeMcs(d)
            | Self::HeNss(d)
            | Self::HeDcm(d)
            | Self::S1gMcs(d)
            | Self::S1gNss(d)
            | Self::EhtMcs(d)
            | Self::EhtNss(d) => buffer[0] = *d,
            Self::MhzWidth(_) | Self::ShortGi | Self::MhzWidth80Plus80 => (),
            Self::Bitrate32(bitrate) => {
                NativeEndian::write_u32(buffer, *bitrate)
            }
            Self::HeGi(d) => buffer[0] = (*d).into(),
            Self::HeRuAlloc(d) => buffer[0] = (*d).into(),
            Self::EhtGi(d) => buffer[0] = (*d).into(),
            Self::EhtRuAlloc(d) => buffer[0] = (*d).into(),
            Self::Other(nlas) => nlas.emit(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for Nl80211RateInfo
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NL80211_RATE_INFO_BITRATE => {
                let err_msg = format!(
                    "Invalid NL80211_RATE_INFO_BITRATE value {payload:?}"
                );
                Self::Bitrate(parse_u16(payload).context(err_msg)?)
            }
            NL80211_RATE_INFO_MCS => {
                let err_msg =
                    format!("Invalid NL80211_RATE_INFO_MCS value {payload:?}");
                Self::Mcs(parse_u8(payload).context(err_msg)?)
            }
            NL80211_RATE_INFO_1_MHZ_WIDTH => Self::MhzWidth(1),
            NL80211_RATE_INFO_2_MHZ_WIDTH => Self::MhzWidth(2),
            NL80211_RATE_INFO_4_MHZ_WIDTH => Self::MhzWidth(4),
            NL80211_RATE_INFO_5_MHZ_WIDTH => Self::MhzWidth(5),
            NL80211_RATE_INFO_8_MHZ_WIDTH => Self::MhzWidth(8),
            NL80211_RATE_INFO_10_MHZ_WIDTH => Self::MhzWidth(10),
            NL80211_RATE_INFO_16_MHZ_WIDTH => Self::MhzWidth(16),
            NL80211_RATE_INFO_40_MHZ_WIDTH => Self::MhzWidth(40),
            NL80211_RATE_INFO_80_MHZ_WIDTH => Self::MhzWidth(80),
            NL80211_RATE_INFO_160_MHZ_WIDTH => Self::MhzWidth(160),
            NL80211_RATE_INFO_320_MHZ_WIDTH => Self::MhzWidth(320),
            NL80211_RATE_INFO_80P80_MHZ_WIDTH => Self::MhzWidth80Plus80,
            NL80211_RATE_INFO_SHORT_GI => Self::ShortGi,
            NL80211_RATE_INFO_BITRATE32 => {
                let err_msg = format!(
                    "Invalid NL80211_RATE_INFO_BITRATE32 value {payload:?}"
                );
                Self::Bitrate32(parse_u32(payload).context(err_msg)?)
            }
            NL80211_RATE_INFO_VHT_MCS => {
                let err_msg = format!(
                    "Invalid NL80211_RATE_INFO_VHT_MCS value {payload:?}"
                );
                Self::VhtMcs(parse_u8(payload).context(err_msg)?)
            }
            NL80211_RATE_INFO_VHT_NSS => {
                let err_msg = format!(
                    "Invalid NL80211_RATE_INFO_VHT_NSS value {payload:?}"
                );
                Self::VhtNss(parse_u8(payload).context(err_msg)?)
            }
            NL80211_RATE_INFO_HE_MCS => {
                let err_msg = format!(
                    "Invalid NL80211_RATE_INFO_HE_MCS value {payload:?}"
                );
                Self::HeMcs(parse_u8(payload).context(err_msg)?)
            }
            NL80211_RATE_INFO_HE_NSS => {
                let err_msg = format!(
                    "Invalid NL80211_RATE_INFO_HE_NSS value {payload:?}"
                );
                Self::HeNss(parse_u8(payload).context(err_msg)?)
            }
            NL80211_RATE_INFO_HE_GI => {
                //
                let err_msg = format!(
                    "Invalid NL80211_RATE_INFO_HE_GI value {payload:?}"
                );
                Self::HeGi(parse_u8(payload).context(err_msg)?.into())
            }
            NL80211_RATE_INFO_HE_DCM => {
                let err_msg = format!(
                    "Invalid NL80211_RATE_INFO_HE_DCM value {payload:?}"
                );
                Self::HeDcm(parse_u8(payload).context(err_msg)?)
            }
            NL80211_RATE_INFO_HE_RU_ALLOC => {
                //
                let err_msg = format!(
                    "Invalid NL80211_RATE_INFO_HE_RU_ALLOC value {payload:?}"
                );
                Self::HeRuAlloc(parse_u8(payload).context(err_msg)?.into())
            }
            NL80211_RATE_INFO_S1G_MCS => {
                let err_msg = format!(
                    "Invalid NL80211_RATE_INFO_S1G_MCS value {payload:?}"
                );
                Self::S1gMcs(parse_u8(payload).context(err_msg)?)
            }
            NL80211_RATE_INFO_S1G_NSS => {
                let err_msg = format!(
                    "Invalid NL80211_RATE_INFO_S1G_NSS value {payload:?}"
                );
                Self::S1gNss(parse_u8(payload).context(err_msg)?)
            }
            NL80211_RATE_INFO_EHT_MCS => {
                let err_msg = format!(
                    "Invalid NL80211_RATE_INFO_EHT_MCS value {payload:?}"
                );
                Self::EhtMcs(parse_u8(payload).context(err_msg)?)
            }
            NL80211_RATE_INFO_EHT_NSS => {
                let err_msg = format!(
                    "Invalid NL80211_RATE_INFO_EHT_NSS value {payload:?}"
                );
                Self::EhtNss(parse_u8(payload).context(err_msg)?)
            }
            NL80211_RATE_INFO_EHT_GI => {
                //
                let err_msg = format!(
                    "Invalid NL80211_RATE_INFO_EHT_GI value {payload:?}"
                );
                Self::EhtGi(parse_u8(payload).context(err_msg)?.into())
            }
            NL80211_RATE_INFO_EHT_RU_ALLOC => {
                //
                let err_msg = format!(
                    "Invalid NL80211_RATE_INFO_EHT_RU_ALLOC value {payload:?}"
                );
                Self::EhtRuAlloc(parse_u8(payload).context(err_msg)?.into())
            }
            _ => Self::Other(
                DefaultNla::parse(buf).context("invalid NLA (unknown kind)")?,
            ),
        })
    }
}

const NL80211_RATE_INFO_HE_GI_0_8: u8 = 0;
const NL80211_RATE_INFO_HE_GI_1_6: u8 = 1;
const NL80211_RATE_INFO_HE_GI_3_2: u8 = 2;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Nl80211HeGi {
    /// 0.8 usec
    Usec0_8,
    /// 1.6 usec
    Usec1_6,
    /// 3.2 usec
    Usec3_2,

    Other(u8),
}

impl From<u8> for Nl80211HeGi {
    fn from(d: u8) -> Self {
        match d {
            NL80211_RATE_INFO_HE_GI_0_8 => Self::Usec0_8,
            NL80211_RATE_INFO_HE_GI_1_6 => Self::Usec1_6,
            NL80211_RATE_INFO_HE_GI_3_2 => Self::Usec3_2,
            _ => Self::Other(d),
        }
    }
}

impl From<Nl80211HeGi> for u8 {
    fn from(v: Nl80211HeGi) -> u8 {
        match v {
            Nl80211HeGi::Usec0_8 => NL80211_RATE_INFO_HE_GI_0_8,
            Nl80211HeGi::Usec1_6 => NL80211_RATE_INFO_HE_GI_1_6,
            Nl80211HeGi::Usec3_2 => NL80211_RATE_INFO_HE_GI_3_2,
            Nl80211HeGi::Other(d) => d,
        }
    }
}

const NL80211_RATE_INFO_HE_RU_ALLOC_26: u8 = 0;
const NL80211_RATE_INFO_HE_RU_ALLOC_52: u8 = 1;
const NL80211_RATE_INFO_HE_RU_ALLOC_106: u8 = 2;
const NL80211_RATE_INFO_HE_RU_ALLOC_242: u8 = 3;
const NL80211_RATE_INFO_HE_RU_ALLOC_484: u8 = 4;
const NL80211_RATE_INFO_HE_RU_ALLOC_996: u8 = 5;
const NL80211_RATE_INFO_HE_RU_ALLOC_2X996: u8 = 6;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Nl80211HeRuAllocation {
    Tone(u32),
    Tone2x996,

    Other(u8),
}

impl From<u8> for Nl80211HeRuAllocation {
    fn from(d: u8) -> Self {
        match d {
            NL80211_RATE_INFO_HE_RU_ALLOC_26 => Self::Tone(26),
            NL80211_RATE_INFO_HE_RU_ALLOC_52 => Self::Tone(52),
            NL80211_RATE_INFO_HE_RU_ALLOC_106 => Self::Tone(106),
            NL80211_RATE_INFO_HE_RU_ALLOC_242 => Self::Tone(242),
            NL80211_RATE_INFO_HE_RU_ALLOC_484 => Self::Tone(484),
            NL80211_RATE_INFO_HE_RU_ALLOC_996 => Self::Tone(996),
            NL80211_RATE_INFO_HE_RU_ALLOC_2X996 => Self::Tone2x996,
            _ => Self::Other(d),
        }
    }
}

impl From<Nl80211HeRuAllocation> for u8 {
    fn from(v: Nl80211HeRuAllocation) -> u8 {
        match v {
            Nl80211HeRuAllocation::Tone(26) => NL80211_RATE_INFO_HE_RU_ALLOC_26,
            Nl80211HeRuAllocation::Tone(52) => NL80211_RATE_INFO_HE_RU_ALLOC_52,
            Nl80211HeRuAllocation::Tone(106) => {
                NL80211_RATE_INFO_HE_RU_ALLOC_106
            }
            Nl80211HeRuAllocation::Tone(242) => {
                NL80211_RATE_INFO_HE_RU_ALLOC_242
            }
            Nl80211HeRuAllocation::Tone(484) => {
                NL80211_RATE_INFO_HE_RU_ALLOC_484
            }
            Nl80211HeRuAllocation::Tone(996) => {
                NL80211_RATE_INFO_HE_RU_ALLOC_996
            }
            Nl80211HeRuAllocation::Tone(_) => {
                log::warn!("Invalid Nl80211HeRuAllocation {v:?}");
                u8::MAX
            }
            Nl80211HeRuAllocation::Tone2x996 => {
                NL80211_RATE_INFO_HE_RU_ALLOC_2X996
            }
            Nl80211HeRuAllocation::Other(d) => d,
        }
    }
}

const NL80211_RATE_INFO_EHT_GI_0_8: u8 = 0;
const NL80211_RATE_INFO_EHT_GI_1_6: u8 = 1;
const NL80211_RATE_INFO_EHT_GI_3_2: u8 = 2;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Nl80211EhtGi {
    /// 0.8 usec
    Usec0_8,
    /// 1.6 usec
    Usec1_6,
    /// 3.2 usec
    Usec3_2,

    Other(u8),
}

impl From<u8> for Nl80211EhtGi {
    fn from(d: u8) -> Self {
        match d {
            NL80211_RATE_INFO_EHT_GI_0_8 => Self::Usec0_8,
            NL80211_RATE_INFO_EHT_GI_1_6 => Self::Usec1_6,
            NL80211_RATE_INFO_EHT_GI_3_2 => Self::Usec3_2,
            _ => Self::Other(d),
        }
    }
}

impl From<Nl80211EhtGi> for u8 {
    fn from(v: Nl80211EhtGi) -> u8 {
        match v {
            Nl80211EhtGi::Usec0_8 => NL80211_RATE_INFO_EHT_GI_0_8,
            Nl80211EhtGi::Usec1_6 => NL80211_RATE_INFO_EHT_GI_1_6,
            Nl80211EhtGi::Usec3_2 => NL80211_RATE_INFO_EHT_GI_3_2,
            Nl80211EhtGi::Other(d) => d,
        }
    }
}

const NL80211_RATE_INFO_EHT_RU_ALLOC_26: u8 = 0;
const NL80211_RATE_INFO_EHT_RU_ALLOC_52: u8 = 1;
const NL80211_RATE_INFO_EHT_RU_ALLOC_52P26: u8 = 2;
const NL80211_RATE_INFO_EHT_RU_ALLOC_106: u8 = 3;
const NL80211_RATE_INFO_EHT_RU_ALLOC_106P26: u8 = 4;
const NL80211_RATE_INFO_EHT_RU_ALLOC_242: u8 = 5;
const NL80211_RATE_INFO_EHT_RU_ALLOC_484: u8 = 6;
const NL80211_RATE_INFO_EHT_RU_ALLOC_484P242: u8 = 7;
const NL80211_RATE_INFO_EHT_RU_ALLOC_996: u8 = 8;
const NL80211_RATE_INFO_EHT_RU_ALLOC_996P484: u8 = 9;
const NL80211_RATE_INFO_EHT_RU_ALLOC_996P484P242: u8 = 10;
const NL80211_RATE_INFO_EHT_RU_ALLOC_2X996: u8 = 11;
const NL80211_RATE_INFO_EHT_RU_ALLOC_2X996P484: u8 = 12;
const NL80211_RATE_INFO_EHT_RU_ALLOC_3X996: u8 = 13;
const NL80211_RATE_INFO_EHT_RU_ALLOC_3X996P484: u8 = 14;
const NL80211_RATE_INFO_EHT_RU_ALLOC_4X996: u8 = 15;

/// EHT RU allocation values
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Nl80211EhtRuAllocation {
    Tone(u32),
    Tone52Plus26,
    Tone106Plus26,
    Tone484Plus242,
    Tone996Plus484,
    Tone996Plus484Plus242,
    Tone2x996,
    Tone2x996Plus484,
    Tone3x996,
    Tone3x996Plus484,
    Tone4x996,

    Other(u8),
}

impl From<u8> for Nl80211EhtRuAllocation {
    fn from(d: u8) -> Self {
        match d {
            NL80211_RATE_INFO_EHT_RU_ALLOC_26 => Self::Tone(26),
            NL80211_RATE_INFO_EHT_RU_ALLOC_52 => Self::Tone(52),
            NL80211_RATE_INFO_EHT_RU_ALLOC_52P26 => Self::Tone52Plus26,
            NL80211_RATE_INFO_EHT_RU_ALLOC_106 => Self::Tone(106),
            NL80211_RATE_INFO_EHT_RU_ALLOC_106P26 => Self::Tone106Plus26,
            NL80211_RATE_INFO_EHT_RU_ALLOC_242 => Self::Tone(242),
            NL80211_RATE_INFO_EHT_RU_ALLOC_484 => Self::Tone(484),
            NL80211_RATE_INFO_EHT_RU_ALLOC_484P242 => Self::Tone484Plus242,
            NL80211_RATE_INFO_EHT_RU_ALLOC_996 => Self::Tone(996),
            NL80211_RATE_INFO_EHT_RU_ALLOC_996P484 => Self::Tone996Plus484,
            NL80211_RATE_INFO_EHT_RU_ALLOC_996P484P242 => {
                Self::Tone996Plus484Plus242
            }
            NL80211_RATE_INFO_EHT_RU_ALLOC_2X996 => Self::Tone2x996,
            NL80211_RATE_INFO_EHT_RU_ALLOC_2X996P484 => Self::Tone2x996Plus484,
            NL80211_RATE_INFO_EHT_RU_ALLOC_3X996 => Self::Tone3x996,
            NL80211_RATE_INFO_EHT_RU_ALLOC_3X996P484 => Self::Tone3x996Plus484,
            NL80211_RATE_INFO_EHT_RU_ALLOC_4X996 => Self::Tone4x996,
            _ => Self::Other(d),
        }
    }
}

impl From<Nl80211EhtRuAllocation> for u8 {
    fn from(v: Nl80211EhtRuAllocation) -> u8 {
        match v {
            Nl80211EhtRuAllocation::Tone(26) => {
                NL80211_RATE_INFO_EHT_RU_ALLOC_26
            }
            Nl80211EhtRuAllocation::Tone(52) => {
                NL80211_RATE_INFO_EHT_RU_ALLOC_52
            }
            Nl80211EhtRuAllocation::Tone(106) => {
                NL80211_RATE_INFO_EHT_RU_ALLOC_106
            }
            Nl80211EhtRuAllocation::Tone(242) => {
                NL80211_RATE_INFO_EHT_RU_ALLOC_242
            }
            Nl80211EhtRuAllocation::Tone(484) => {
                NL80211_RATE_INFO_EHT_RU_ALLOC_484
            }
            Nl80211EhtRuAllocation::Tone(996) => {
                NL80211_RATE_INFO_EHT_RU_ALLOC_996
            }
            Nl80211EhtRuAllocation::Tone(_) => {
                log::warn!("Invalid Nl80211EhtRuAllocation {v:?}");
                u8::MAX
            }
            Nl80211EhtRuAllocation::Tone52Plus26 => {
                NL80211_RATE_INFO_EHT_RU_ALLOC_52P26
            }
            Nl80211EhtRuAllocation::Tone106Plus26 => {
                NL80211_RATE_INFO_EHT_RU_ALLOC_106P26
            }
            Nl80211EhtRuAllocation::Tone484Plus242 => {
                NL80211_RATE_INFO_EHT_RU_ALLOC_484P242
            }
            Nl80211EhtRuAllocation::Tone996Plus484 => {
                NL80211_RATE_INFO_EHT_RU_ALLOC_996P484
            }
            Nl80211EhtRuAllocation::Tone996Plus484Plus242 => {
                NL80211_RATE_INFO_EHT_RU_ALLOC_996P484P242
            }
            Nl80211EhtRuAllocation::Tone2x996 => {
                NL80211_RATE_INFO_EHT_RU_ALLOC_2X996
            }
            Nl80211EhtRuAllocation::Tone2x996Plus484 => {
                NL80211_RATE_INFO_EHT_RU_ALLOC_2X996P484
            }
            Nl80211EhtRuAllocation::Tone3x996 => {
                NL80211_RATE_INFO_EHT_RU_ALLOC_3X996
            }
            Nl80211EhtRuAllocation::Tone3x996Plus484 => {
                NL80211_RATE_INFO_EHT_RU_ALLOC_3X996P484
            }
            Nl80211EhtRuAllocation::Tone4x996 => {
                NL80211_RATE_INFO_EHT_RU_ALLOC_4X996
            }
            Nl80211EhtRuAllocation::Other(d) => d,
        }
    }
}
