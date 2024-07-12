// SPDX-License-Identifier: MIT

use std::convert::TryInto;

use anyhow::Context;
use byteorder::{ByteOrder, NativeEndian};
use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer},
    parsers::{parse_u16, parse_u32, parse_u64, parse_u8},
    Emitable, Parseable,
};

use std::fmt::Debug;

const NL80211_BSS_BSSID: u16 = 1;
const NL80211_BSS_FREQUENCY: u16 = 2;
const NL80211_BSS_TSF: u16 = 3;
const NL80211_BSS_BEACON_INTERVAL: u16 = 4;
const NL80211_BSS_CAPABILITY: u16 = 5;
const NL80211_BSS_INFORMATION_ELEMENTS: u16 = 6;
const NL80211_BSS_SIGNAL_MBM: u16 = 7;
const NL80211_BSS_SIGNAL_UNSPEC: u16 = 8;
const NL80211_BSS_STATUS: u16 = 9;
const NL80211_BSS_SEEN_MS_AGO: u16 = 10;
const NL80211_BSS_BEACON_IES: u16 = 11;
const NL80211_BSS_CHAN_WIDTH: u16 = 12;
const NL80211_BSS_BEACON_TSF: u16 = 13;
const NL80211_BSS_PRESP_DATA: u16 = 14;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Nl80211BssInfo {
    // Bssid(hex),
    Frequency(u32),
    // Tsf(TSF),
    BeaconInterval(u16),
    // Capability(capability),
    InformationElements(Vec<Nl80211InformationElements>),
    SignalMbm(i32),
    SignalUnspec(u8),
    Status(u32),
    SeenMsAgo(u32),
    // BeaconIes(elementsBinary),
    ChanWidth(u32),
    BeaconTsf(u64),
    // PrespData(hex),
    Other(DefaultNla),
}

impl Nla for Nl80211BssInfo {
    fn value_len(&self) -> usize {
        match self {
            Self::SignalUnspec(_) => 1,
            Self::BeaconInterval(_) => 2,
            Self::Frequency(_)
            | Self::SignalMbm(_)
            | Self::Status(_)
            | Self::SeenMsAgo(_)
            | Self::ChanWidth(_) => 4,
            Self::BeaconTsf(_) => 8,
            Self::InformationElements(_) => todo!(),
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Nl80211BssInfo::Frequency(_) => NL80211_BSS_FREQUENCY,
            Nl80211BssInfo::BeaconInterval(_) => NL80211_BSS_BEACON_INTERVAL,
            Nl80211BssInfo::InformationElements(_) => {
                NL80211_BSS_INFORMATION_ELEMENTS
            }
            Nl80211BssInfo::SignalMbm(_) => NL80211_BSS_SIGNAL_MBM,
            Nl80211BssInfo::SignalUnspec(_) => NL80211_BSS_SIGNAL_UNSPEC,
            Nl80211BssInfo::Status(_) => NL80211_BSS_STATUS,
            Nl80211BssInfo::SeenMsAgo(_) => NL80211_BSS_SEEN_MS_AGO,
            Nl80211BssInfo::ChanWidth(_) => NL80211_BSS_CHAN_WIDTH,
            Nl80211BssInfo::BeaconTsf(_) => NL80211_BSS_BEACON_TSF,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Nl80211BssInfo::SignalUnspec(d) => buffer[0] = *d,
            Nl80211BssInfo::BeaconInterval(d) => {
                NativeEndian::write_u16(buffer, *d)
            }
            Nl80211BssInfo::Frequency(d)
            | Nl80211BssInfo::Status(d)
            | Nl80211BssInfo::SeenMsAgo(d)
            | Nl80211BssInfo::ChanWidth(d) => {
                NativeEndian::write_u32(buffer, *d)
            }
            Nl80211BssInfo::SignalMbm(d) => NativeEndian::write_i32(buffer, *d),
            Nl80211BssInfo::BeaconTsf(d) => NativeEndian::write_u64(buffer, *d),
            Nl80211BssInfo::InformationElements(_) => todo!(),
            Self::Other(ref attr) => attr.emit(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for Nl80211BssInfo
{
    fn parse(
        buf: &NlaBuffer<&'a T>,
    ) -> Result<Self, netlink_packet_utils::DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NL80211_BSS_FREQUENCY => {
                let err_msg = format!(
                    "Invalid NL80211_BSS_FREQUENCY value {:?}",
                    payload
                );
                Self::Frequency(parse_u32(payload).context(err_msg)?)
            }
            NL80211_BSS_BEACON_INTERVAL => {
                let err_msg = format!(
                    "Invalid NL80211_BSS_BEACON_INTERVAL value {:?}",
                    payload
                );
                Self::BeaconInterval(parse_u16(payload).context(err_msg)?)
            }
            NL80211_BSS_INFORMATION_ELEMENTS => Self::InformationElements(
                Nl80211InformationElements::parse_vec(buf).unwrap(),
            ),
            NL80211_BSS_SIGNAL_MBM => {
                let err_msg = format!(
                    "Invalid NL80211_BSS_SIGNAL_MBM value {:?}",
                    payload
                );
                Self::SignalMbm(i32::from_ne_bytes(
                    payload.try_into().context(err_msg)?,
                ))
            }
            NL80211_BSS_SIGNAL_UNSPEC => {
                let err_msg = format!(
                    "Invalid NL80211_BSS_SIGNAL_UNSPEC value {:?}",
                    payload
                );
                Self::SignalUnspec(parse_u8(payload).context(err_msg)?)
            }
            NL80211_BSS_STATUS => {
                let err_msg =
                    format!("Invalid NL80211_BSS_STATUS value {:?}", payload);
                Self::Status(parse_u32(payload).context(err_msg)?)
            }
            NL80211_BSS_SEEN_MS_AGO => {
                let err_msg = format!(
                    "Invalid NL80211_BSS_SEEN_MS_AGO value {:?}",
                    payload
                );
                Self::SeenMsAgo(parse_u32(payload).context(err_msg)?)
            }
            NL80211_BSS_CHAN_WIDTH => {
                let err_msg = format!(
                    "Invalid NL80211_BSS_CHAN_WIDTH value {:?}",
                    payload
                );
                Self::ChanWidth(parse_u32(payload).context(err_msg)?)
            }
            NL80211_BSS_BEACON_TSF => {
                let err_msg = format!(
                    "Invalid NL80211_BSS_BEACON_TSF value {:?}",
                    payload
                );
                Self::BeaconTsf(parse_u64(payload).context(err_msg)?)
            }
            _ => Self::Other(
                DefaultNla::parse(buf).context("invalid NLA (unknown kind)")?,
            ),
        })
    }
}

const NL80211_BSS_ELEMENTS_SSID: u8 = 0;
const NL80211_BSS_ELEMENTS_SUPPORTED_RATES: u8 = 1;
const NL80211_BSS_ELEMENTS_CHANNEL: u8 = 3;
const NL80211_BSS_ELEMENTS_TIM: u8 = 5;
const NL80211_BSS_ELEMENTS_RSN: u8 = 48;
const NL80211_BSS_ELEMENTS_HT_OPERATION: u8 = 61;
const NL80211_BSS_ELEMENTS_EXTENDED_RATE: u8 = 50;
const NL80211_BSS_ELEMENTS_VHT_OPERATION: u8 = 192;
const NL80211_BSS_ELEMENTS_VENDOR: u8 = 221;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Nl80211InformationElements {
    Ssid(String),
    Other(u8, Vec<u8>),
}

impl Nl80211InformationElements {
    fn parse_vec<T: AsRef<[u8]> + ?Sized>(
        buf: &NlaBuffer<&T>,
    ) -> Result<Vec<Self>, netlink_packet_utils::DecodeError> {
        let mut result = Vec::new();
        let payload = buf.value();

        let mut offset = 0;

        while offset < payload.len() {
            let msg_type = parse_u8(&payload[offset..][..1])?;
            let length = parse_u8(&payload[offset + 1..][..1])? as usize;

            match msg_type {
                NL80211_BSS_ELEMENTS_SSID => result.push(Self::Ssid(
                    String::from_utf8(payload[offset + 2..][..length].to_vec())
                        .map_err(anyhow::Error::from)?,
                )),
                msg_type => result.push(Self::Other(
                    msg_type,
                    payload[offset + 2..][..length].to_owned(),
                )),
            }

            offset += length + 2;
        }

        Ok(result)
    }
}
