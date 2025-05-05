// SPDX-License-Identifier: MIT

// Most documentation comments are copied and modified from linux kernel
// include/uapi/linux/nl80211.h which is holding these license disclaimer:
/*
 * 802.11 netlink interface public header
 *
 * Copyright 2006-2010 Johannes Berg <johannes@sipsolutions.net>
 * Copyright 2008 Michael Wu <flamingice@sourmilk.net>
 * Copyright 2008 Luis Carlos Cobo <luisca@cozybit.com>
 * Copyright 2008 Michael Buesch <m@bues.ch>
 * Copyright 2008, 2009 Luis R. Rodriguez <lrodriguez@atheros.com>
 * Copyright 2008 Jouni Malinen <jouni.malinen@atheros.com>
 * Copyright 2008 Colin McCabe <colin@cozybit.com>
 * Copyright 2015-2017	Intel Deutschland GmbH
 * Copyright (C) 2018-2024 Intel Corporation
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 */

use anyhow::Context;
use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer, NlasIterator},
    parsers::{parse_u16, parse_u32, parse_u8},
    DecodeError, Emitable, Parseable, ParseableParametrized,
};

use crate::{
    bytes::{write_u16, write_u32},
    Nl80211EhtMacCapInfo, Nl80211EhtMcsNssSupp, Nl80211EhtPhyCapInfo,
    Nl80211EhtPpeThres, Nl80211He6GhzCapa, Nl80211HeMacCapInfo,
    Nl80211HeMcsNssSupp, Nl80211HePhyCapInfo, Nl80211HePpeThreshold,
    Nl80211HtCaps, Nl80211HtMcsInfo, Nl80211VhtCapInfo, Nl80211VhtMcsInfo,
};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Nl80211Band {
    pub kind: Nl80211BandType,
    pub info: Vec<Nl80211BandInfo>,
}

impl Nla for Nl80211Band {
    fn value_len(&self) -> usize {
        self.info.as_slice().buffer_len()
    }

    fn kind(&self) -> u16 {
        self.kind.into()
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        self.info.as_slice().emit(buffer)
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for Nl80211Band {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let band_type = Nl80211BandType::from(buf.kind());
        let payload = buf.value();
        let mut nlas = Vec::new();
        for nla in NlasIterator::new(payload) {
            let err_msg =
                format!("Invalid NL80211_ATTR_WIPHY_BANDS value {nla:?}");
            let nla = &nla.context(err_msg.clone())?;
            nlas.push(Nl80211BandInfo::parse(nla)?);
        }
        Ok(Self {
            kind: band_type,
            info: nlas,
        })
    }
}

const NL80211_BAND_2GHZ: u16 = 0;
const NL80211_BAND_5GHZ: u16 = 1;
const NL80211_BAND_60GHZ: u16 = 2;
const NL80211_BAND_6GHZ: u16 = 3;
const NL80211_BAND_S1GHZ: u16 = 4;
const NL80211_BAND_LC: u16 = 5;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Nl80211BandType {
    Band2GHz,
    Band5GHz,
    Band60GHz,
    Band6GHz,
    BandS1GHz,
    /// light communication band
    BandLc,
    Other(u16),
}

impl From<u16> for Nl80211BandType {
    fn from(d: u16) -> Self {
        match d {
            NL80211_BAND_2GHZ => Self::Band2GHz,
            NL80211_BAND_5GHZ => Self::Band5GHz,
            NL80211_BAND_60GHZ => Self::Band60GHz,
            NL80211_BAND_6GHZ => Self::Band6GHz,
            NL80211_BAND_S1GHZ => Self::BandS1GHz,
            NL80211_BAND_LC => Self::BandLc,
            _ => Self::Other(d),
        }
    }
}

impl From<Nl80211BandType> for u16 {
    fn from(v: Nl80211BandType) -> u16 {
        match v {
            Nl80211BandType::Band2GHz => NL80211_BAND_2GHZ,
            Nl80211BandType::Band5GHz => NL80211_BAND_5GHZ,
            Nl80211BandType::Band60GHz => NL80211_BAND_60GHZ,
            Nl80211BandType::Band6GHz => NL80211_BAND_6GHZ,
            Nl80211BandType::BandS1GHz => NL80211_BAND_S1GHZ,
            Nl80211BandType::BandLc => NL80211_BAND_LC,
            Nl80211BandType::Other(d) => d,
        }
    }
}

bitflags::bitflags! {
    /// If not bands are set, it means don't care and the device will decide
    /// what to use
    #[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
    #[non_exhaustive]
    pub struct Nl80211BandTypes: u32 {
        const Band2GHz = 1 << NL80211_BAND_2GHZ;
        const Band5GHz = 1 << NL80211_BAND_5GHZ;
        const Band60GHz = 1 << NL80211_BAND_60GHZ;
        const Band6GHz = 1 << NL80211_BAND_6GHZ;
        const BandS1GHz = 1<< NL80211_BAND_S1GHZ;
        /// light communication band (placeholder)
        const BandLc = 1 << NL80211_BAND_LC;
    }
}

impl Nl80211BandTypes {
    pub const LENGTH: usize = 4;

    pub fn parse(raw: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self::from_bits_retain(parse_u32(raw).context(format!(
            "Invalid Nl80211BandTypes payload {raw:?}"
        ))?))
    }
}

impl Emitable for Nl80211BandTypes {
    fn buffer_len(&self) -> usize {
        Self::LENGTH
    }

    fn emit(&self, buffer: &mut [u8]) {
        buffer.copy_from_slice(&self.bits().to_ne_bytes())
    }
}

const NL80211_BAND_ATTR_FREQS: u16 = 1;
const NL80211_BAND_ATTR_RATES: u16 = 2;
const NL80211_BAND_ATTR_HT_MCS_SET: u16 = 3;
const NL80211_BAND_ATTR_HT_CAPA: u16 = 4;
const NL80211_BAND_ATTR_HT_AMPDU_FACTOR: u16 = 5;
const NL80211_BAND_ATTR_HT_AMPDU_DENSITY: u16 = 6;
const NL80211_BAND_ATTR_VHT_MCS_SET: u16 = 7;
const NL80211_BAND_ATTR_VHT_CAPA: u16 = 8;
const NL80211_BAND_ATTR_IFTYPE_DATA: u16 = 9;
const NL80211_BAND_ATTR_EDMG_CHANNELS: u16 = 10;
const NL80211_BAND_ATTR_EDMG_BW_CONFIG: u16 = 11;
// TODO: Kernel has no properly defined struct for 802.11ah sub-1G MCS and CAPA,
// postpone the deserialization.
// const NL80211_BAND_ATTR_S1G_MCS_NSS_SET: u16 = 12;
// const NL80211_BAND_ATTR_S1G_CAPA: u16 = 13;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Nl80211BandInfo {
    /// Supported frequencies in this band.
    Freqs(Vec<Nl80211Frequency>),
    /// Supported bitrates in this band.
    Rates(Vec<Vec<Nl80211Rate>>),
    /// The MCS set as defined in 802.11n(WIFI 4).
    HtMcsSet(Nl80211HtMcsInfo),
    /// HT capabilities, as in the HT information IE.
    HtCapa(Nl80211HtCaps),
    /// Maximum A-MPDU length factor, as in 802.11n(WIFI 4).
    HtAmpduFactor(u8),
    /// Minimum A-MPDU spacing, as in 802.11n(WIFI 4).
    HtAmpduDensity(u8),
    /// The MCS set as defined in 802.11ac(WIFI 5).
    VhtMcsSet(Nl80211VhtMcsInfo),
    /// VHT capabilities, as in the HT information IE
    VhtCap(Nl80211VhtCapInfo),
    /// Interface type data
    IftypeData(Vec<Nl80211BandIftypeData>),
    /// Bitmap that indicates the 2.16 GHz channel(s) that are allowed to be
    /// used for EDMG transmissions. Defined by IEEE P802.11ay/D4.0 section
    /// 9.4.2.251.
    EdmgChannels(u8),
    /// Channel BW Configuration subfield encodes the allowed channel bandwidth
    /// configurations.
    EdmgBwConfig(u8),
    Other(DefaultNla),
}

impl Nla for Nl80211BandInfo {
    fn value_len(&self) -> usize {
        match self {
            Self::Freqs(s) => s.as_slice().buffer_len(),
            Self::Rates(s) => {
                Nl80211RateAttrsList::from(s).as_slice().buffer_len()
            }
            Self::HtMcsSet(_) => Nl80211HtMcsInfo::LENGTH,
            Self::HtCapa(_) => 2,
            Self::HtAmpduFactor(_) => 1,
            Self::HtAmpduDensity(_) => 1,
            Self::VhtMcsSet(_) => Nl80211VhtMcsInfo::LENGTH,
            Self::VhtCap(_) => Nl80211VhtCapInfo::LENGTH,
            Self::IftypeData(s) => s.as_slice().buffer_len(),
            Self::EdmgChannels(_) => 1,
            Self::EdmgBwConfig(_) => 1,
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Freqs(_) => NL80211_BAND_ATTR_FREQS,
            Self::Rates(_) => NL80211_BAND_ATTR_RATES,
            Self::HtMcsSet(_) => NL80211_BAND_ATTR_HT_MCS_SET,
            Self::HtCapa(_) => NL80211_BAND_ATTR_HT_CAPA,
            Self::HtAmpduFactor(_) => NL80211_BAND_ATTR_HT_AMPDU_FACTOR,
            Self::HtAmpduDensity(_) => NL80211_BAND_ATTR_HT_AMPDU_DENSITY,
            Self::VhtMcsSet(_) => NL80211_BAND_ATTR_VHT_MCS_SET,
            Self::VhtCap(_) => NL80211_BAND_ATTR_VHT_CAPA,
            Self::IftypeData(_) => NL80211_BAND_ATTR_IFTYPE_DATA,
            Self::EdmgChannels(_) => NL80211_BAND_ATTR_EDMG_CHANNELS,
            Self::EdmgBwConfig(_) => NL80211_BAND_ATTR_EDMG_BW_CONFIG,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Freqs(d) => d.as_slice().emit(buffer),
            Self::Rates(s) => {
                Nl80211RateAttrsList::from(s).as_slice().emit(buffer)
            }
            Self::HtMcsSet(d) => d.emit(buffer),
            Self::HtCapa(d) => d.emit(buffer),
            Self::HtAmpduFactor(d) => buffer[0] = *d,
            Self::HtAmpduDensity(d) => buffer[0] = *d,
            Self::VhtMcsSet(d) => d.emit(buffer),
            Self::VhtCap(d) => d.emit(buffer),
            Self::IftypeData(d) => d.as_slice().emit(buffer),
            Self::EdmgChannels(d) => buffer[0] = *d,
            Self::EdmgBwConfig(d) => buffer[0] = *d,
            Self::Other(attr) => attr.emit(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for Nl80211BandInfo
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NL80211_BAND_ATTR_FREQS => {
                let err_msg = format!(
                    "Invalid NL80211_BAND_ATTR_FREQS value {payload:?}"
                );
                let mut nlas = Vec::new();
                for nla in NlasIterator::new(payload) {
                    let nla = &nla.context(err_msg.clone())?;
                    nlas.push(Nl80211Frequency::parse(nla)?);
                }
                Self::Freqs(nlas)
            }
            NL80211_BAND_ATTR_RATES => {
                let err_msg = format!(
                    "Invalid NL80211_BAND_ATTR_RATES value {payload:?}"
                );
                let mut nlas = Vec::new();
                for (index, nla) in NlasIterator::new(payload).enumerate() {
                    let nla = &nla.context(err_msg.clone())?;
                    nlas.push(
                        Nl80211RateAttrs::parse_with_param(nla, index as u16)
                            .context(err_msg.clone())?
                            .attributes,
                    );
                }
                Self::Rates(nlas)
            }
            NL80211_BAND_ATTR_HT_MCS_SET => {
                Self::HtMcsSet(Nl80211HtMcsInfo::parse(payload)?)
            }
            NL80211_BAND_ATTR_HT_CAPA => {
                Self::HtCapa(Nl80211HtCaps::parse(payload)?)
            }
            NL80211_BAND_ATTR_HT_AMPDU_FACTOR => {
                let err_msg = format!(
                    "Invalid NL80211_BAND_ATTR_HT_AMPDU_FACTOR value {payload:?}"
                );
                Self::HtAmpduFactor(parse_u8(payload).context(err_msg)?)
            }
            NL80211_BAND_ATTR_HT_AMPDU_DENSITY => {
                let err_msg = format!(
                    "Invalid NL80211_BAND_ATTR_HT_AMPDU_DENSITY value {payload:?}"
                );
                Self::HtAmpduDensity(parse_u8(payload).context(err_msg)?)
            }
            NL80211_BAND_ATTR_VHT_MCS_SET => {
                Self::VhtMcsSet(Nl80211VhtMcsInfo::parse(payload)?)
            }
            NL80211_BAND_ATTR_VHT_CAPA => {
                Self::VhtCap(Nl80211VhtCapInfo::parse(payload)?)
            }
            NL80211_BAND_ATTR_IFTYPE_DATA => {
                let err_msg = format!(
                    "Invalid NL80211_BAND_ATTR_IFTYPE_DATA value {payload:?}"
                );
                let mut nlas = Vec::new();
                for nla in NlasIterator::new(payload) {
                    let nla = &nla.context(err_msg.clone())?;
                    nlas.push(
                        Nl80211BandIftypeData::parse(nla)
                            .context(err_msg.clone())?,
                    );
                }
                Self::IftypeData(nlas)
            }
            NL80211_BAND_ATTR_EDMG_CHANNELS => {
                let err_msg = format!(
                    "Invalid NL80211_BAND_ATTR_EDMG_CHANNELS value {payload:?}"
                );
                Self::EdmgChannels(parse_u8(payload).context(err_msg)?)
            }
            NL80211_BAND_ATTR_EDMG_BW_CONFIG => {
                let err_msg = format!(
                    "Invalid NL80211_BAND_ATTR_EDMG_BW_CONFIG value {payload:?}"
                );
                Self::EdmgBwConfig(parse_u8(payload).context(err_msg)?)
            }
            _ => Self::Other(
                DefaultNla::parse(buf).context("invalid NLA (unknown kind)")?,
            ),
        })
    }
}

const NL80211_BAND_IFTYPE_ATTR_IFTYPES: u16 = 1;
const NL80211_BAND_IFTYPE_ATTR_HE_CAP_MAC: u16 = 2;
const NL80211_BAND_IFTYPE_ATTR_HE_CAP_PHY: u16 = 3;
const NL80211_BAND_IFTYPE_ATTR_HE_CAP_MCS_SET: u16 = 4;
const NL80211_BAND_IFTYPE_ATTR_HE_CAP_PPE: u16 = 5;
const NL80211_BAND_IFTYPE_ATTR_HE_6GHZ_CAPA: u16 = 6;
const NL80211_BAND_IFTYPE_ATTR_VENDOR_ELEMS: u16 = 7;
const NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MAC: u16 = 8;
const NL80211_BAND_IFTYPE_ATTR_EHT_CAP_PHY: u16 = 9;
const NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MCS_SET: u16 = 10;
const NL80211_BAND_IFTYPE_ATTR_EHT_CAP_PPE: u16 = 11;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum Nl80211BandIftypeData {
    IfTypes(Vec<Nl80211IfType>),
    HeCapMac(Nl80211HeMacCapInfo),
    HeCapPhy(Nl80211HePhyCapInfo),
    HeCapMcsSet(Nl80211HeMcsNssSupp),
    HeCapPpeThreshold(Nl80211HePpeThreshold),
    He6ghzCapa(Nl80211He6GhzCapa),
    /// Vendor specific data
    VendorElems(Vec<u8>),
    EhtCapMac(Nl80211EhtMacCapInfo),
    EhtCapPhy(Nl80211EhtPhyCapInfo),
    EhtCapMcsSet(Nl80211EhtMcsNssSupp),
    EhtCapPpe(Nl80211EhtPpeThres),
    Other(DefaultNla),
}

impl Nla for Nl80211BandIftypeData {
    fn value_len(&self) -> usize {
        match self {
            Self::IfTypes(s) => Nl80211IfTypeList(s.clone()).value_len(),
            Self::HeCapMac(s) => s.buffer_len(),
            Self::HeCapPhy(s) => s.buffer_len(),
            Self::HeCapMcsSet(s) => s.buffer_len(),
            Self::HeCapPpeThreshold(s) => s.buffer_len(),
            Self::He6ghzCapa(s) => s.buffer_len(),
            Self::VendorElems(s) => s.len(),
            Self::EhtCapMac(s) => s.buffer_len(),
            Self::EhtCapPhy(s) => s.buffer_len(),
            Self::EhtCapMcsSet(s) => s.buffer_len(),
            Self::EhtCapPpe(s) => s.buffer_len(),
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::IfTypes(_) => NL80211_BAND_IFTYPE_ATTR_IFTYPES,
            Self::HeCapMac(_) => NL80211_BAND_IFTYPE_ATTR_HE_CAP_MAC,
            Self::HeCapPhy(_) => NL80211_BAND_IFTYPE_ATTR_HE_CAP_PHY,
            Self::HeCapMcsSet(_) => NL80211_BAND_IFTYPE_ATTR_HE_CAP_MCS_SET,
            Self::HeCapPpeThreshold(_) => NL80211_BAND_IFTYPE_ATTR_HE_CAP_PPE,
            Self::He6ghzCapa(_) => NL80211_BAND_IFTYPE_ATTR_HE_6GHZ_CAPA,
            Self::VendorElems(_) => NL80211_BAND_IFTYPE_ATTR_VENDOR_ELEMS,
            Self::EhtCapMac(_) => NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MAC,
            Self::EhtCapPhy(_) => NL80211_BAND_IFTYPE_ATTR_EHT_CAP_PHY,
            Self::EhtCapMcsSet(_) => NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MCS_SET,
            Self::EhtCapPpe(_) => NL80211_BAND_IFTYPE_ATTR_EHT_CAP_PPE,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::IfTypes(d) => {
                Nl80211IfTypeList(d.clone()).0.as_slice().emit(buffer)
            }
            Self::HeCapMac(d) => d.emit(buffer),
            Self::HeCapPhy(d) => d.emit(buffer),
            Self::HeCapMcsSet(d) => d.emit(buffer),
            Self::HeCapPpeThreshold(d) => d.emit(buffer),
            Self::He6ghzCapa(d) => d.emit(buffer),
            Self::VendorElems(d) => buffer[..d.len()].copy_from_slice(d),
            Self::EhtCapMac(d) => d.emit(buffer),
            Self::EhtCapPhy(d) => d.emit(buffer),
            Self::EhtCapMcsSet(d) => d.emit(buffer),
            Self::EhtCapPpe(d) => d.emit(buffer),
            Self::Other(attr) => attr.emit(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for Nl80211BandIftypeData
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NL80211_BAND_IFTYPE_ATTR_IFTYPES => Self::IfTypes(
                Nl80211IfTypeList::parse(buf)
                    .context(
                        "Invalid NLA for NL80211_BAND_IFTYPE_ATTR_IFTYPES",
                    )?
                    .0,
            ),
            NL80211_BAND_IFTYPE_ATTR_HE_CAP_MAC => {
                if payload.len() < Nl80211HeMacCapInfo::LENGTH {
                    return Err(format!(
                        "NL80211_BAND_IFTYPE_ATTR_HE_CAP_MAC value \
                        length is less than expected {}: {:?}",
                        Nl80211HeMacCapInfo::LENGTH,
                        payload
                    )
                    .into());
                }
                Self::HeCapMac(Nl80211HeMacCapInfo::new(payload))
            }
            NL80211_BAND_IFTYPE_ATTR_HE_CAP_PHY => {
                if payload.len() < Nl80211HePhyCapInfo::LENGTH {
                    return Err(format!(
                        "NL80211_BAND_IFTYPE_ATTR_HE_CAP_PHY value \
                        length is less than expected {}: {:?}",
                        Nl80211HePhyCapInfo::LENGTH,
                        payload
                    )
                    .into());
                }
                Self::HeCapPhy(Nl80211HePhyCapInfo::new(payload))
            }
            NL80211_BAND_IFTYPE_ATTR_HE_CAP_MCS_SET => {
                if payload.len() < Nl80211HeMcsNssSupp::LENGTH {
                    return Err(format!(
                        "NL80211_BAND_IFTYPE_ATTR_HE_CAP_MCS_SET value \
                        length is less than expected {}: {:?}",
                        Nl80211HeMcsNssSupp::LENGTH,
                        payload
                    )
                    .into());
                }
                Self::HeCapMcsSet(Nl80211HeMcsNssSupp::parse(payload)?)
            }
            NL80211_BAND_IFTYPE_ATTR_HE_CAP_PPE => {
                if payload.len() < Nl80211HePpeThreshold::LENGTH {
                    return Err(format!(
                        "NL80211_BAND_IFTYPE_ATTR_HE_CAP_PPE value \
                        length is less than expected {}: {:?}",
                        Nl80211HePpeThreshold::LENGTH,
                        payload
                    )
                    .into());
                }
                Self::HeCapPpeThreshold(Nl80211HePpeThreshold::new(payload))
            }
            NL80211_BAND_IFTYPE_ATTR_HE_6GHZ_CAPA => {
                if payload.len() < Nl80211He6GhzCapa::LENGTH {
                    return Err(format!(
                        "NL80211_BAND_IFTYPE_ATTR_HE_6GHZ_CAPA value \
                        length is less than expected {}: {:?}",
                        Nl80211He6GhzCapa::LENGTH,
                        payload
                    )
                    .into());
                }
                Self::He6ghzCapa(Nl80211He6GhzCapa::new(payload))
            }
            NL80211_BAND_IFTYPE_ATTR_VENDOR_ELEMS => {
                Self::VendorElems(payload.to_vec())
            }
            NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MAC => {
                if payload.len() < Nl80211EhtMacCapInfo::LENGTH {
                    return Err(format!(
                        "NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MAC value \
                        length is less than expected {}: {:?}",
                        Nl80211EhtMacCapInfo::LENGTH,
                        payload
                    )
                    .into());
                }
                Self::EhtCapMac(Nl80211EhtMacCapInfo::new(payload))
            }
            NL80211_BAND_IFTYPE_ATTR_EHT_CAP_PHY => {
                if payload.len() < Nl80211EhtPhyCapInfo::LENGTH {
                    return Err(format!(
                        "NL80211_BAND_IFTYPE_ATTR_EHT_CAP_PHY value \
                        length is less than expected {}: {:?}",
                        Nl80211EhtPhyCapInfo::LENGTH,
                        payload
                    )
                    .into());
                }
                Self::EhtCapPhy(Nl80211EhtPhyCapInfo::new(payload))
            }
            NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MCS_SET => {
                Self::EhtCapMcsSet(Nl80211EhtMcsNssSupp::parse(payload)?)
            }
            NL80211_BAND_IFTYPE_ATTR_EHT_CAP_PPE => {
                Self::EhtCapPpe(Nl80211EhtPpeThres::new(payload))
            }
            _ => Self::Other(
                DefaultNla::parse(buf).context("invalid NLA (unknown kind)")?,
            ),
        })
    }
}

const NL80211_IFTYPE_ADHOC: u16 = 1;
const NL80211_IFTYPE_STATION: u16 = 2;
const NL80211_IFTYPE_AP: u16 = 3;
const NL80211_IFTYPE_AP_VLAN: u16 = 4;
const NL80211_IFTYPE_WDS: u16 = 5;
const NL80211_IFTYPE_MONITOR: u16 = 6;
const NL80211_IFTYPE_MESH_POINT: u16 = 7;
const NL80211_IFTYPE_P2P_CLIENT: u16 = 8;
const NL80211_IFTYPE_P2P_GO: u16 = 9;
const NL80211_IFTYPE_P2P_DEVICE: u16 = 10;
const NL80211_IFTYPE_OCB: u16 = 11;
const NL80211_IFTYPE_NAN: u16 = 12;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Nl80211IfType {
    Adhoc,
    /// aka: managed or client
    Station,
    Ap,
    ApVlan,
    Wds,
    Monitor,
    MeshPoint,
    P2pClient,
    P2pGo,
    P2pDevice,
    Ocb,
    Nan,
    Other(u16),
}

impl From<u16> for Nl80211IfType {
    fn from(d: u16) -> Self {
        match d {
            NL80211_IFTYPE_ADHOC => Self::Adhoc,
            NL80211_IFTYPE_STATION => Self::Station,
            NL80211_IFTYPE_AP => Self::Ap,
            NL80211_IFTYPE_AP_VLAN => Self::ApVlan,
            NL80211_IFTYPE_WDS => Self::Wds,
            NL80211_IFTYPE_MONITOR => Self::Monitor,
            NL80211_IFTYPE_MESH_POINT => Self::MeshPoint,
            NL80211_IFTYPE_P2P_CLIENT => Self::P2pClient,
            NL80211_IFTYPE_P2P_GO => Self::P2pGo,
            NL80211_IFTYPE_P2P_DEVICE => Self::P2pDevice,
            NL80211_IFTYPE_OCB => Self::Ocb,
            NL80211_IFTYPE_NAN => Self::Nan,
            _ => Self::Other(d),
        }
    }
}

impl From<&Nl80211IfType> for u16 {
    fn from(v: &Nl80211IfType) -> Self {
        match v {
            Nl80211IfType::Adhoc => NL80211_IFTYPE_ADHOC,
            Nl80211IfType::Station => NL80211_IFTYPE_STATION,
            Nl80211IfType::Ap => NL80211_IFTYPE_AP,
            Nl80211IfType::ApVlan => NL80211_IFTYPE_AP_VLAN,
            Nl80211IfType::Wds => NL80211_IFTYPE_WDS,
            Nl80211IfType::Monitor => NL80211_IFTYPE_MONITOR,
            Nl80211IfType::MeshPoint => NL80211_IFTYPE_MESH_POINT,
            Nl80211IfType::P2pClient => NL80211_IFTYPE_P2P_CLIENT,
            Nl80211IfType::P2pGo => NL80211_IFTYPE_P2P_GO,
            Nl80211IfType::P2pDevice => NL80211_IFTYPE_P2P_DEVICE,
            Nl80211IfType::Ocb => NL80211_IFTYPE_OCB,
            Nl80211IfType::Nan => NL80211_IFTYPE_NAN,
            Nl80211IfType::Other(d) => *d,
        }
    }
}

// The kernel function `nl80211_put_iftypes()` is using mode number as NLA kind
struct Nl80211IfTypeList(Vec<Nl80211IfType>);

impl std::ops::Deref for Nl80211IfTypeList {
    type Target = Vec<Nl80211IfType>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Nla for Nl80211IfType {
    fn value_len(&self) -> usize {
        0
    }

    fn emit_value(&self, _buffer: &mut [u8]) {}

    fn kind(&self) -> u16 {
        self.into()
    }
}

impl Nla for Nl80211IfTypeList {
    fn value_len(&self) -> usize {
        self.0.as_slice().buffer_len()
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        self.0.as_slice().emit(buffer)
    }

    fn kind(&self) -> u16 {
        NL80211_BAND_IFTYPE_ATTR_IFTYPES
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for Nl80211IfTypeList
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        let mut if_types: Vec<Nl80211IfType> = Vec::new();
        for nla in NlasIterator::new(payload) {
            let nla =
                &nla.context("invalid NL80211_BAND_IFTYPE_ATTR_IFTYPES value")?;
            if_types.push(nla.kind().into());
        }
        Ok(Self(if_types))
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Nl80211Frequency {
    pub index: u16,
    pub info: Vec<Nl80211FrequencyInfo>,
}

impl Nla for Nl80211Frequency {
    fn value_len(&self) -> usize {
        self.info.as_slice().buffer_len()
    }

    fn kind(&self) -> u16 {
        self.index
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        self.info.as_slice().emit(buffer)
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for Nl80211Frequency
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let index = buf.kind();
        let payload = buf.value();
        let mut nlas = Vec::new();
        for nla in NlasIterator::new(payload) {
            let err_msg =
                format!("Invalid NL80211_BAND_ATTR_FREQS value {nla:?}");
            let nla = &nla.context(err_msg.clone())?;
            nlas.push(Nl80211FrequencyInfo::parse(nla)?);
        }
        Ok(Self { index, info: nlas })
    }
}

const NL80211_FREQUENCY_ATTR_FREQ: u16 = 1;
const NL80211_FREQUENCY_ATTR_DISABLED: u16 = 2;
const NL80211_FREQUENCY_ATTR_NO_IR: u16 = 3;
// Obsoleted, same as NL80211_FREQUENCY_ATTR_NO_IR
const __NL80211_FREQUENCY_ATTR_NO_IBSS: u16 = 4;
const NL80211_FREQUENCY_ATTR_RADAR: u16 = 5;
const NL80211_FREQUENCY_ATTR_MAX_TX_POWER: u16 = 6;
const NL80211_FREQUENCY_ATTR_DFS_STATE: u16 = 7;
const NL80211_FREQUENCY_ATTR_DFS_TIME: u16 = 8;
const NL80211_FREQUENCY_ATTR_NO_HT40_MINUS: u16 = 9;
const NL80211_FREQUENCY_ATTR_NO_HT40_PLUS: u16 = 10;
const NL80211_FREQUENCY_ATTR_NO_80MHZ: u16 = 11;
const NL80211_FREQUENCY_ATTR_NO_160MHZ: u16 = 12;
const NL80211_FREQUENCY_ATTR_DFS_CAC_TIME: u16 = 13;
const NL80211_FREQUENCY_ATTR_INDOOR_ONLY: u16 = 14;
const NL80211_FREQUENCY_ATTR_IR_CONCURRENT: u16 = 15;
const NL80211_FREQUENCY_ATTR_NO_20MHZ: u16 = 16;
const NL80211_FREQUENCY_ATTR_NO_10MHZ: u16 = 17;
const NL80211_FREQUENCY_ATTR_WMM: u16 = 18;
const NL80211_FREQUENCY_ATTR_NO_HE: u16 = 19;
const NL80211_FREQUENCY_ATTR_OFFSET: u16 = 20;
const NL80211_FREQUENCY_ATTR_1MHZ: u16 = 21;
const NL80211_FREQUENCY_ATTR_2MHZ: u16 = 22;
const NL80211_FREQUENCY_ATTR_4MHZ: u16 = 23;
const NL80211_FREQUENCY_ATTR_8MHZ: u16 = 24;
const NL80211_FREQUENCY_ATTR_16MHZ: u16 = 25;
const NL80211_FREQUENCY_ATTR_NO_320MHZ: u16 = 26;
const NL80211_FREQUENCY_ATTR_NO_EHT: u16 = 27;
const NL80211_FREQUENCY_ATTR_PSD: u16 = 28;
const NL80211_FREQUENCY_ATTR_DFS_CONCURRENT: u16 = 29;
const NL80211_FREQUENCY_ATTR_NO_6GHZ_VLP_CLIENT: u16 = 30;
const NL80211_FREQUENCY_ATTR_NO_6GHZ_AFC_CLIENT: u16 = 31;
const NL80211_FREQUENCY_ATTR_CAN_MONITOR: u16 = 32;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Nl80211FrequencyInfo {
    /// Frequency in MHz
    Freq(u32),
    /// Channel is disabled in current regulatory domain
    Disabled,
    /// No mechanisms that initiate radiation are permitted on this channel,
    /// this includes sending probe requests, or modes of operation that
    /// require beaconing.
    NoIr,
    /// Obsoleted, same as [Nl80211FrequencyInfo::NoIr]
    NoIbss,
    /// Radar detection is mandatory on this channel in current regulatory
    /// domain.
    Radar,
    /// Maximum transmission power in mBm (100 * dBm)
    MaxTxPower(u32),
    /// Current state for DFS
    DfsState(Nl80211DfsState),
    /// time in milliseconds for how long this channel is in this DFS state
    DfsTime(u32),
    /// HT40- isn't possible with this channel as the control channel
    NoHt40Minus,
    /// HT40+ isn't possible with this channel as the control channel
    NoHt40Plus,
    /// Any 80 MHz channel using this channel as the primary or any of the
    /// secondary channels isn't possible, this includes 80+80 channels
    No80Mhz,
    /// Any 160 MHz (but not 80+80) channel using this channel as the primary
    /// or any of the secondary channels isn't possible
    No160Mhz,
    /// DFS CAC time in milliseconds.
    DfsCacTime(u32),
    /// Only indoor use is permitted on this channel. A channel that has the
    /// INDOOR_ONLY attribute can only be used when there is a clear assessment
    /// that the device is operating in an indoor surroundings, i.e., it is
    /// connected to AC power (and not through portable DC inverters) or is
    /// under the control of a master that is acting as an AP and is connected
    /// to AC power.
    IndoorOnly,
    /// IR operation is allowed on this channel if it's connected concurrently
    /// to a BSS on the same channel on the 2 GHz band or to a channel in
    /// the same UNII band (on the 5 GHz band), and IEEE80211_CHAN_RADAR is
    /// not set. Instantiating a GO or TDLS off-channel on a channel that
    /// has the IR_CONCURRENT attribute set can be done when there is a
    /// clear assessment that the device is operating under the guidance of
    /// an authorized master, i.e., setting up a GO or TDLS off-channel
    /// while the device is also connected to an AP with DFS and radar
    /// detection on the UNII band (it is up to user-space, i.e.,
    /// wpa_supplicant to perform the required verifications). Using this
    /// attribute for IR is disallowed for master interfaces (IBSS, AP).
    IrConcurrent,
    /// 20 MHz operation is not allowed on this channel in current regulatory
    /// domain.
    No20Mhz,
    /// 10 MHz operation is not allowed on this channel in current regulatory
    /// domain.
    No10Mhz,
    /// this channel has WMM limitations.
    Wmm(Vec<Vec<Nl80211WmmRule>>),
    /// HE operation is not allowed on this channel in current regulatory
    /// domain.
    NoHe,
    /// frequency offset in KHz
    Offset(u32),
    /// 1 MHz operation is allowed
    Allow1Mhz,
    /// 2 MHz operation is allowed
    Allow2Mhz,
    /// 4 MHz operation is allowed
    Allow4Mhz,
    /// 8 MHz operation is allowed
    Allow8Mhz,
    /// 16 MHz operation is allowed
    Allow16Mhz,
    /// any 320 MHz channel using this channel
    /// as the primary or any of the secondary channels isn't possible
    No320Mhz,
    /// EHT operation is not allowed on this channel in current regulatory
    /// domain.
    NoEht,
    /// Power spectral density (in dBm) that is allowed on this channel in
    /// current regulatory domain.
    Psd(i8),
    /// Operation on this channel is allowed for peer-to-peer or adhoc
    /// communication under the control of a DFS master which operates on the
    /// same channel (FCC-594280 D01 Section B.3). Should be used together with
    /// `NL80211_RRF_DFS` only.
    DfsConcurrent,
    /// Client connection to VLP AP not allowed using this channel
    No6GhzVlpClient,
    /// Client connection to AFC AP not allowed using this channel
    No6GhzAfcclient,
    /// This channel can be used in monitor mode despite other (regulatory)
    /// restrictions, even if the channel is otherwise completely disabled.
    CanMonitor,
    /// Place holder for new attribute of `NL80211_BAND_ATTR_FREQS`
    Other(DefaultNla),
}

impl Nla for Nl80211FrequencyInfo {
    fn value_len(&self) -> usize {
        match self {
            Self::Freq(_) => 4,
            Self::Disabled => 0,
            Self::NoIr => 0,
            Self::Radar => 0,
            Self::NoIbss => 0,
            Self::MaxTxPower(_) => 4,
            Self::DfsState(_) => 4,
            Self::DfsTime(_) => 4,
            Self::NoHt40Minus => 0,
            Self::NoHt40Plus => 0,
            Self::No80Mhz => 0,
            Self::No160Mhz => 0,
            Self::DfsCacTime(_) => 4,
            Self::IndoorOnly => 0,
            Self::IrConcurrent => 0,
            Self::No20Mhz => 0,
            Self::No10Mhz => 0,
            Self::Wmm(ref v) => {
                Nl80211WmmRuleAttrsList::from(v).as_slice().buffer_len()
            }
            Self::NoHe => 0,
            Self::Offset(_) => 4,
            Self::Allow1Mhz => 0,
            Self::Allow2Mhz => 0,
            Self::Allow4Mhz => 0,
            Self::Allow8Mhz => 0,
            Self::Allow16Mhz => 0,
            Self::No320Mhz => 0,
            Self::NoEht => 0,
            Self::Psd(_) => 1,
            Self::DfsConcurrent => 0,
            Self::No6GhzVlpClient => 0,
            Self::No6GhzAfcclient => 0,
            Self::CanMonitor => 0,
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Freq(_) => NL80211_FREQUENCY_ATTR_FREQ,
            Self::Disabled => NL80211_FREQUENCY_ATTR_DISABLED,
            Self::NoIr => NL80211_FREQUENCY_ATTR_NO_IR,
            Self::NoIbss => __NL80211_FREQUENCY_ATTR_NO_IBSS,
            Self::Radar => NL80211_FREQUENCY_ATTR_RADAR,
            Self::MaxTxPower(_) => NL80211_FREQUENCY_ATTR_MAX_TX_POWER,
            Self::DfsState(_) => NL80211_FREQUENCY_ATTR_DFS_STATE,
            Self::DfsTime(_) => NL80211_FREQUENCY_ATTR_DFS_TIME,
            Self::NoHt40Minus => NL80211_FREQUENCY_ATTR_NO_HT40_MINUS,
            Self::NoHt40Plus => NL80211_FREQUENCY_ATTR_NO_HT40_PLUS,
            Self::No80Mhz => NL80211_FREQUENCY_ATTR_NO_80MHZ,
            Self::No160Mhz => NL80211_FREQUENCY_ATTR_NO_160MHZ,
            Self::DfsCacTime(_) => NL80211_FREQUENCY_ATTR_DFS_CAC_TIME,
            Self::IndoorOnly => NL80211_FREQUENCY_ATTR_INDOOR_ONLY,
            Self::IrConcurrent => NL80211_FREQUENCY_ATTR_IR_CONCURRENT,
            Self::No20Mhz => NL80211_FREQUENCY_ATTR_NO_20MHZ,
            Self::No10Mhz => NL80211_FREQUENCY_ATTR_NO_10MHZ,
            Self::Wmm(_) => NL80211_FREQUENCY_ATTR_WMM,
            Self::NoHe => NL80211_FREQUENCY_ATTR_NO_HE,
            Self::Offset(_) => NL80211_FREQUENCY_ATTR_OFFSET,
            Self::Allow1Mhz => NL80211_FREQUENCY_ATTR_1MHZ,
            Self::Allow2Mhz => NL80211_FREQUENCY_ATTR_2MHZ,
            Self::Allow4Mhz => NL80211_FREQUENCY_ATTR_4MHZ,
            Self::Allow8Mhz => NL80211_FREQUENCY_ATTR_8MHZ,
            Self::Allow16Mhz => NL80211_FREQUENCY_ATTR_16MHZ,
            Self::No320Mhz => NL80211_FREQUENCY_ATTR_NO_320MHZ,
            Self::NoEht => NL80211_FREQUENCY_ATTR_NO_EHT,
            Self::Psd(_) => NL80211_FREQUENCY_ATTR_PSD,
            Self::DfsConcurrent => NL80211_FREQUENCY_ATTR_DFS_CONCURRENT,
            Self::No6GhzVlpClient => NL80211_FREQUENCY_ATTR_NO_6GHZ_VLP_CLIENT,
            Self::No6GhzAfcclient => NL80211_FREQUENCY_ATTR_NO_6GHZ_AFC_CLIENT,
            Self::CanMonitor => NL80211_FREQUENCY_ATTR_CAN_MONITOR,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Freq(d)
            | Self::MaxTxPower(d)
            | Self::DfsTime(d)
            | Self::DfsCacTime(d) => write_u32(buffer, *d),
            Self::DfsState(d) => write_u32(buffer, u32::from(d)),
            Self::Disabled
            | Self::NoIr
            | Self::NoIbss
            | Self::Radar
            | Self::NoHt40Minus
            | Self::NoHt40Plus
            | Self::No80Mhz
            | Self::No160Mhz
            | Self::IndoorOnly
            | Self::IrConcurrent
            | Self::No20Mhz
            | Self::No10Mhz
            | Self::NoHe
            | Self::Allow1Mhz
            | Self::Allow2Mhz
            | Self::Allow4Mhz
            | Self::Allow8Mhz
            | Self::Allow16Mhz
            | Self::No320Mhz
            | Self::NoEht
            | Self::DfsConcurrent
            | Self::No6GhzVlpClient
            | Self::No6GhzAfcclient
            | Self::CanMonitor => (),
            Self::Psd(d) => buffer[0] = *d as u8,
            Self::Offset(d) => write_u32(buffer, *d),
            Self::Wmm(ref v) => {
                Nl80211WmmRuleAttrsList::from(v).as_slice().emit(buffer)
            }
            Self::Other(ref attr) => attr.emit(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for Nl80211FrequencyInfo
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NL80211_FREQUENCY_ATTR_FREQ => {
                Self::Freq(parse_u32(payload).context(format!(
                    "Invalid NL80211_FREQUENCY_ATTR_FREQ value: {payload:?}"
                ))?)
            }
            NL80211_FREQUENCY_ATTR_DISABLED => Self::Disabled,
            NL80211_FREQUENCY_ATTR_NO_IR => Self::NoIr,
            __NL80211_FREQUENCY_ATTR_NO_IBSS => Self::NoIbss,
            NL80211_FREQUENCY_ATTR_RADAR => Self::Radar,
            NL80211_FREQUENCY_ATTR_MAX_TX_POWER => {
                Self::MaxTxPower(parse_u32(payload).context(format!(
                    "Invalid NL80211_FREQUENCY_ATTR_MAX_TX_POWER value: {payload:?}"
                ))?)
            }
            NL80211_FREQUENCY_ATTR_DFS_STATE => Self::DfsState(
                parse_u32(payload)
                    .context(format!(
                    "Invalid NL80211_FREQUENCY_ATTR_MAX_TX_POWER value: {payload:?}"
                ))?
                    .into(),
            ),

            NL80211_FREQUENCY_ATTR_DFS_TIME => {
                Self::DfsTime(parse_u32(payload).context(format!(
                    "Invalid NL80211_FREQUENCY_ATTR_DFS_TIME value: {payload:?}"
                ))?)
            }
            NL80211_FREQUENCY_ATTR_NO_HT40_MINUS => Self::NoHt40Minus,
            NL80211_FREQUENCY_ATTR_NO_HT40_PLUS => Self::NoHt40Plus,
            NL80211_FREQUENCY_ATTR_NO_80MHZ => Self::No80Mhz,
            NL80211_FREQUENCY_ATTR_NO_160MHZ => Self::No160Mhz,
            NL80211_FREQUENCY_ATTR_DFS_CAC_TIME => {
                Self::DfsCacTime(parse_u32(payload).context(format!(
                    "Invalid NL80211_FREQUENCY_ATTR_DFS_CAC_TIME value: {payload:?}"
                ))?)
            }
            NL80211_FREQUENCY_ATTR_INDOOR_ONLY => Self::IndoorOnly,
            NL80211_FREQUENCY_ATTR_IR_CONCURRENT => Self::IrConcurrent,
            NL80211_FREQUENCY_ATTR_NO_20MHZ => Self::No20Mhz,
            NL80211_FREQUENCY_ATTR_NO_10MHZ => Self::No10Mhz,
            NL80211_FREQUENCY_ATTR_WMM => {
                let err_msg = format!(
                    "Invalid NL80211_FREQUENCY_ATTR_WMM value {payload:?}"
                );
                let mut nlas = Vec::new();
                for (index, nla) in NlasIterator::new(payload).enumerate() {
                    let nla = &nla.context(err_msg.clone())?;
                    nlas.push(
                        Nl80211WmmRuleAttrs::parse_with_param(
                            nla,
                            index as u16,
                        )
                        .context(err_msg.clone())?
                        .attributes,
                    );
                }
                Self::Wmm(nlas)
            }
            NL80211_FREQUENCY_ATTR_NO_HE => Self::NoHe,
            NL80211_FREQUENCY_ATTR_OFFSET => {
                Self::Offset(parse_u32(payload).context(format!(
                    "Invalid NL80211_FREQUENCY_ATTR_OFFSET value {payload:?}"
                ))?)
            }
            NL80211_FREQUENCY_ATTR_1MHZ => Self::Allow1Mhz,
            NL80211_FREQUENCY_ATTR_2MHZ => Self::Allow2Mhz,
            NL80211_FREQUENCY_ATTR_4MHZ => Self::Allow4Mhz,
            NL80211_FREQUENCY_ATTR_8MHZ => Self::Allow8Mhz,
            NL80211_FREQUENCY_ATTR_16MHZ => Self::Allow16Mhz,
            NL80211_FREQUENCY_ATTR_NO_320MHZ => Self::No320Mhz,
            NL80211_FREQUENCY_ATTR_NO_EHT => Self::NoEht,
            NL80211_FREQUENCY_ATTR_PSD => {
                if payload.is_empty() {
                    return Err(
                        "Got empty NL80211_FREQUENCY_ATTR_PSD payload".into()
                    );
                }
                Self::Psd(payload[0] as i8)
            }
            NL80211_FREQUENCY_ATTR_DFS_CONCURRENT => Self::DfsConcurrent,
            NL80211_FREQUENCY_ATTR_NO_6GHZ_VLP_CLIENT => Self::No6GhzVlpClient,
            NL80211_FREQUENCY_ATTR_NO_6GHZ_AFC_CLIENT => Self::No6GhzAfcclient,
            NL80211_FREQUENCY_ATTR_CAN_MONITOR => Self::CanMonitor,
            _ => Self::Other(
                DefaultNla::parse(buf).context("invalid NLA (unknown kind)")?,
            ),
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
struct Nl80211RateAttrsList(Vec<Nl80211RateAttrs>);

impl std::ops::Deref for Nl80211RateAttrsList {
    type Target = Vec<Nl80211RateAttrs>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<&Vec<Vec<Nl80211Rate>>> for Nl80211RateAttrsList {
    fn from(attributes: &Vec<Vec<Nl80211Rate>>) -> Self {
        Self(
            attributes
                .iter()
                .cloned()
                .enumerate()
                .map(|(index, attributes)| Nl80211RateAttrs {
                    index: index as u16,
                    attributes,
                })
                .collect(),
        )
    }
}

// `NL80211_BAND_ATTR_RATES` is a two levels array.
// The second level is using index as NLA kind.
#[derive(Debug, PartialEq, Eq, Clone)]
struct Nl80211RateAttrs {
    index: u16,
    attributes: Vec<Nl80211Rate>,
}

impl Nla for Nl80211RateAttrs {
    fn value_len(&self) -> usize {
        self.attributes.as_slice().buffer_len()
    }

    fn kind(&self) -> u16 {
        self.index
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        self.attributes.as_slice().emit(buffer);
    }
}

impl<'a, T> ParseableParametrized<NlaBuffer<&'a T>, u16> for Nl80211RateAttrs
where
    T: AsRef<[u8]> + ?Sized,
{
    fn parse_with_param(
        buf: &NlaBuffer<&'a T>,
        index: u16,
    ) -> Result<Self, DecodeError> {
        let payload = buf.value();
        let err_msg =
            format!("Invalid NL80211_BAND_ATTR_RATES value {payload:?}");
        let mut attributes = Vec::new();
        for nla in NlasIterator::new(payload) {
            let nla = &nla.context(err_msg.clone())?;
            attributes.push(Nl80211Rate::parse(nla)?);
        }
        Ok(Self { index, attributes })
    }
}

const NL80211_BITRATE_ATTR_RATE: u16 = 1;
const NL80211_BITRATE_ATTR_2GHZ_SHORTPREAMBLE: u16 = 2;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Nl80211Rate {
    /// Bitrate in units of 100 kbps.
    Rate(u32),
    /// Short preamble supported in 2.4 GHz band.
    Support2GhzShortpreamble,
    Other(DefaultNla),
}

impl Nla for Nl80211Rate {
    fn value_len(&self) -> usize {
        match self {
            Self::Rate(_) => 4,
            Self::Support2GhzShortpreamble => 0,
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Rate(_) => NL80211_BITRATE_ATTR_RATE,
            Self::Support2GhzShortpreamble => {
                NL80211_BITRATE_ATTR_2GHZ_SHORTPREAMBLE
            }
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Rate(d) => write_u32(buffer, *d),
            Self::Support2GhzShortpreamble => (),
            Self::Other(ref attr) => attr.emit(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for Nl80211Rate {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NL80211_BITRATE_ATTR_RATE => {
                Self::Rate(parse_u32(payload).context(format!(
                    "Invalid NL80211_BITRATE_ATTR_RATE value {payload:?}"
                ))?)
            }
            NL80211_BITRATE_ATTR_2GHZ_SHORTPREAMBLE => {
                Self::Support2GhzShortpreamble
            }
            _ => Self::Other(
                DefaultNla::parse(buf).context("invalid NLA (unknown kind)")?,
            ),
        })
    }
}

const NL80211_DFS_USABLE: u32 = 0;
const NL80211_DFS_UNAVAILABLE: u32 = 1;
const NL80211_DFS_AVAILABLE: u32 = 2;

/// DFS states for channels
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Nl80211DfsState {
    /// The channel can be used, but channel availability check (CAC) must be
    /// performed before using it for AP or IBSS.
    Usable,
    /// A radar has been detected on this channel, it is therefore marked as
    /// not available.
    Unavailable,
    /// The channel has been CAC checked and is available.
    Available,
    /// Place holder for new state
    Other(u32),
}

impl From<u32> for Nl80211DfsState {
    fn from(d: u32) -> Self {
        match d {
            NL80211_DFS_USABLE => Self::Usable,
            NL80211_DFS_UNAVAILABLE => Self::Unavailable,
            NL80211_DFS_AVAILABLE => Self::Available,
            _ => Self::Other(d),
        }
    }
}

impl From<&Nl80211DfsState> for u32 {
    fn from(v: &Nl80211DfsState) -> Self {
        match v {
            Nl80211DfsState::Usable => NL80211_DFS_USABLE,
            Nl80211DfsState::Unavailable => NL80211_DFS_UNAVAILABLE,
            Nl80211DfsState::Available => NL80211_DFS_AVAILABLE,
            Nl80211DfsState::Other(d) => *d,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
struct Nl80211WmmRuleAttrsList(Vec<Nl80211WmmRuleAttrs>);

impl std::ops::Deref for Nl80211WmmRuleAttrsList {
    type Target = Vec<Nl80211WmmRuleAttrs>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<&Vec<Vec<Nl80211WmmRule>>> for Nl80211WmmRuleAttrsList {
    fn from(attributes: &Vec<Vec<Nl80211WmmRule>>) -> Self {
        Self(
            attributes
                .iter()
                .cloned()
                .enumerate()
                .map(|(index, attributes)| Nl80211WmmRuleAttrs {
                    index: index as u16,
                    attributes,
                })
                .collect(),
        )
    }
}

// `NL80211_FREQUENCY_ATTR_WMM` is a two levels array.
// The second level is using index as NLA kind.
#[derive(Debug, PartialEq, Eq, Clone)]
struct Nl80211WmmRuleAttrs {
    index: u16,
    attributes: Vec<Nl80211WmmRule>,
}

impl Nla for Nl80211WmmRuleAttrs {
    fn value_len(&self) -> usize {
        self.attributes.as_slice().buffer_len()
    }

    fn kind(&self) -> u16 {
        self.index
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        self.attributes.as_slice().emit(buffer);
    }
}

impl<'a, T> ParseableParametrized<NlaBuffer<&'a T>, u16> for Nl80211WmmRuleAttrs
where
    T: AsRef<[u8]> + ?Sized,
{
    fn parse_with_param(
        buf: &NlaBuffer<&'a T>,
        index: u16,
    ) -> Result<Self, DecodeError> {
        let payload = buf.value();
        let err_msg =
            format!("Invalid NL80211_FREQUENCY_ATTR_WMM value {payload:?}");
        let mut attributes = Vec::new();
        for nla in NlasIterator::new(payload) {
            let nla = &nla.context(err_msg.clone())?;
            attributes.push(Nl80211WmmRule::parse(nla)?);
        }
        Ok(Self { index, attributes })
    }
}

const NL80211_WMMR_CW_MIN: u16 = 1;
const NL80211_WMMR_CW_MAX: u16 = 2;
const NL80211_WMMR_AIFSN: u16 = 3;
const NL80211_WMMR_TXOP: u16 = 4;

/// DFS states for channels
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Nl80211WmmRule {
    /// Minimum contention window slot
    CwMin(u16),
    /// Maximum contention window slot
    CwMax(u16),
    /// Arbitration Inter Frame Space
    Aifsn(u8),
    /// Maximum allowed tx operation time
    Txop(u16),
    /// Place holder for new entry of `enum nl80211_wmm_rule`
    Other(DefaultNla),
}

impl Nla for Nl80211WmmRule {
    fn value_len(&self) -> usize {
        match self {
            Self::CwMin(_) | Self::CwMax(_) | Self::Txop(_) => 2,
            Self::Aifsn(_) => 1,
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::CwMin(_) => NL80211_WMMR_CW_MIN,
            Self::CwMax(_) => NL80211_WMMR_CW_MAX,
            Self::Aifsn(_) => NL80211_WMMR_AIFSN,
            Self::Txop(_) => NL80211_WMMR_TXOP,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::CwMin(d) | Self::CwMax(d) | Self::Txop(d) => {
                write_u16(buffer, *d)
            }
            Self::Aifsn(d) => buffer[0] = *d,
            Self::Other(ref attr) => attr.emit(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for Nl80211WmmRule
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NL80211_WMMR_CW_MIN => Self::CwMin(parse_u16(payload).context(
                format!("Invalid NL80211_WMMR_CW_MIN value {payload:?}"),
            )?),
            NL80211_WMMR_CW_MAX => Self::CwMax(parse_u16(payload).context(
                format!("Invalid NL80211_WMMR_CW_MAX value {payload:?}"),
            )?),
            NL80211_WMMR_AIFSN => Self::Aifsn(parse_u8(payload).context(
                format!("Invalid NL80211_WMMR_AIFSN value {payload:?}"),
            )?),
            NL80211_WMMR_TXOP => Self::Txop(parse_u16(payload).context(
                format!("Invalid NL80211_WMMR_CW_MAX value {payload:?}"),
            )?),
            _ => Self::Other(
                DefaultNla::parse(buf).context("invalid NLA (unknown kind)")?,
            ),
        })
    }
}
