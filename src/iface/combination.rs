// SPDX-License-Identifier: MIT

use anyhow::Context;
use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer, NlasIterator},
    parsers::parse_u32,
    DecodeError, Emitable, Parseable, ParseableParametrized,
};

use crate::{bytes::write_u32, Nl80211InterfaceType, Nl80211InterfaceTypes};

const NL80211_IFACE_COMB_LIMITS: u16 = 1;
const NL80211_IFACE_COMB_MAXNUM: u16 = 2;
const NL80211_IFACE_COMB_STA_AP_BI_MATCH: u16 = 3;
const NL80211_IFACE_COMB_NUM_CHANNELS: u16 = 4;
const NL80211_IFACE_COMB_RADAR_DETECT_WIDTHS: u16 = 5;
const NL80211_IFACE_COMB_RADAR_DETECT_REGIONS: u16 = 6;
const NL80211_IFACE_COMB_BI_MIN_GCD: u16 = 7;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct Nl80211IfaceComb {
    pub index: u16,
    pub attributes: Vec<Nl80211IfaceCombAttribute>,
}

impl Nla for Nl80211IfaceComb {
    fn value_len(&self) -> usize {
        self.attributes.as_slice().buffer_len()
    }

    fn kind(&self) -> u16 {
        self.index + 1
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        self.attributes.as_slice().emit(buffer)
    }
}

impl<'a, T> ParseableParametrized<NlaBuffer<&'a T>, u16> for Nl80211IfaceComb
where
    T: AsRef<[u8]> + ?Sized,
{
    fn parse_with_param(
        buf: &NlaBuffer<&'a T>,
        index: u16,
    ) -> Result<Self, DecodeError> {
        let payload = buf.value();
        let err_msg = format!(
            "Invalid NL80211_IFACE_COMB_LIMITS {payload:?} index {index}"
        );
        let mut attributes = Vec::new();
        for nla in NlasIterator::new(payload) {
            let nla = &nla.context(err_msg.clone())?;
            attributes.push(Nl80211IfaceCombAttribute::parse(nla)?);
        }
        Ok(Self { index, attributes })
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum Nl80211IfaceCombAttribute {
    Limits(Vec<Nl80211IfaceCombLimit>),
    Maxnum(u32),
    StaApiBiMatch,
    NumChannels(u32),
    RadarDetectWidths(u32),
    RadarDetectRegins(u32),
    BiMinGcd(u32),
    Other(DefaultNla),
}

impl Nla for Nl80211IfaceCombAttribute {
    fn value_len(&self) -> usize {
        match self {
            Self::Limits(v) => v.as_slice().buffer_len(),
            Self::StaApiBiMatch => 0,
            Self::Maxnum(_)
            | Self::NumChannels(_)
            | Self::RadarDetectWidths(_)
            | Self::RadarDetectRegins(_)
            | Self::BiMinGcd(_) => 4,
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Limits(_) => NL80211_IFACE_COMB_LIMITS,
            Self::Maxnum(_) => NL80211_IFACE_COMB_MAXNUM,
            Self::StaApiBiMatch => NL80211_IFACE_COMB_STA_AP_BI_MATCH,
            Self::NumChannels(_) => NL80211_IFACE_COMB_NUM_CHANNELS,
            Self::RadarDetectWidths(_) => {
                NL80211_IFACE_COMB_RADAR_DETECT_WIDTHS
            }
            Self::RadarDetectRegins(_) => {
                NL80211_IFACE_COMB_RADAR_DETECT_REGIONS
            }
            Self::BiMinGcd(_) => NL80211_IFACE_COMB_BI_MIN_GCD,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Maxnum(d)
            | Self::NumChannels(d)
            | Self::RadarDetectWidths(d)
            | Self::RadarDetectRegins(d)
            | Self::BiMinGcd(d) => write_u32(buffer, *d),
            Self::StaApiBiMatch => (),
            Self::Limits(v) => v.as_slice().emit(buffer),
            Self::Other(attr) => attr.emit(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for Nl80211IfaceCombAttribute
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NL80211_IFACE_COMB_LIMITS => {
                let err_msg =
                    format!("Invalid NL80211_IFACE_COMB_LIMITS {payload:?}");
                let mut nlas = Vec::new();
                for (index, nla) in NlasIterator::new(payload).enumerate() {
                    let nla = &nla.context(err_msg.clone())?;
                    nlas.push(Nl80211IfaceCombLimit::parse_with_param(
                        nla,
                        index as u16,
                    )?);
                }
                Self::Limits(nlas)
            }
            NL80211_IFACE_COMB_MAXNUM => {
                Self::Maxnum(parse_u32(payload).context(format!(
                    "Invalid NL80211_IFACE_COMB_MAXNUM {payload:?}"
                ))?)
            }
            NL80211_IFACE_COMB_STA_AP_BI_MATCH => Self::StaApiBiMatch,
            NL80211_IFACE_COMB_NUM_CHANNELS => {
                Self::NumChannels(parse_u32(payload).context(format!(
                    "Invalid NL80211_IFACE_COMB_NUM_CHANNELS {payload:?}"
                ))?)
            }
            NL80211_IFACE_COMB_RADAR_DETECT_WIDTHS => {
                Self::RadarDetectWidths(parse_u32(payload).context(format!(
                    "Invalid NL80211_IFACE_COMB_RADAR_DETECT_WIDTHS \
                    {payload:?}"
                ))?)
            }
            NL80211_IFACE_COMB_RADAR_DETECT_REGIONS => {
                Self::RadarDetectRegins(parse_u32(payload).context(format!(
                    "Invalid NL80211_IFACE_COMB_RADAR_DETECT_REGIONS \
                    {payload:?}"
                ))?)
            }
            NL80211_IFACE_COMB_BI_MIN_GCD => {
                Self::BiMinGcd(parse_u32(payload).context(format!(
                    "Invalid NL80211_IFACE_COMB_BI_MIN_GCD {payload:?}"
                ))?)
            }
            _ => Self::Other(
                DefaultNla::parse(buf).context("invalid NLA (unknown kind)")?,
            ),
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct Nl80211IfaceCombLimit {
    pub index: u16,
    pub attributes: Vec<Nl80211IfaceCombLimitAttribute>,
}

impl Nla for Nl80211IfaceCombLimit {
    fn value_len(&self) -> usize {
        self.attributes.as_slice().buffer_len()
    }

    fn kind(&self) -> u16 {
        self.index + 1
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        self.attributes.as_slice().emit(buffer)
    }
}

impl<'a, T> ParseableParametrized<NlaBuffer<&'a T>, u16>
    for Nl80211IfaceCombLimit
where
    T: AsRef<[u8]> + ?Sized,
{
    fn parse_with_param(
        buf: &NlaBuffer<&'a T>,
        index: u16,
    ) -> Result<Self, DecodeError> {
        let payload = buf.value();
        let err_msg =
            format!("Invalid NL80211_IFACE_COMB_LIMITS {:?}", payload);
        let mut attributes = Vec::new();
        for nla in NlasIterator::new(payload) {
            let nla = &nla.context(err_msg.clone())?;
            attributes.push(Nl80211IfaceCombLimitAttribute::parse(nla)?);
        }
        Ok(Self { index, attributes })
    }
}

const NL80211_IFACE_LIMIT_MAX: u16 = 1;
const NL80211_IFACE_LIMIT_TYPES: u16 = 2;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum Nl80211IfaceCombLimitAttribute {
    Max(u32),
    Iftypes(Vec<Nl80211InterfaceType>),
    Other(DefaultNla),
}

impl Nla for Nl80211IfaceCombLimitAttribute {
    fn value_len(&self) -> usize {
        match self {
            Self::Max(_) => 4,
            Self::Iftypes(v) => {
                Nl80211InterfaceTypes::from(v).as_slice().buffer_len()
            }
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Max(_) => NL80211_IFACE_LIMIT_MAX,
            Self::Iftypes(_) => NL80211_IFACE_LIMIT_TYPES,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Max(d) => write_u32(buffer, *d),
            Self::Iftypes(v) => {
                Nl80211InterfaceTypes::from(v).as_slice().emit(buffer)
            }
            Self::Other(attr) => attr.emit(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for Nl80211IfaceCombLimitAttribute
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NL80211_IFACE_LIMIT_MAX => Self::Max(parse_u32(payload).context(
                format!("Invalid NL80211_IFACE_LIMIT_MAX {payload:?}"),
            )?),
            NL80211_IFACE_LIMIT_TYPES => Self::Iftypes(
                Nl80211InterfaceTypes::parse(
                    payload,
                    "NL80211_IFACE_LIMIT_TYPES",
                )?
                .0,
            ),
            _ => Self::Other(
                DefaultNla::parse(buf).context("invalid NLA (unknown kind)")?,
            ),
        })
    }
}
