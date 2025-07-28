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

use std::convert::TryInto;
use std::fmt::Debug;

use anyhow::Context;
use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer},
    parsers::{parse_u16, parse_u32, parse_u64, parse_u8},
    DecodeError, Emitable, Parseable,
};

use crate::{
    bytes::{write_i32, write_u16, write_u32, write_u64},
    RawNl80211Elements,
};

bitflags::bitflags! {
    /// IEEE 802.11-202, 9.4.1.4 Capability Information field
    #[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
    #[non_exhaustive]
    pub struct Nl80211BssCapabilities: u16 {
        const Ess = 1 << 0;
        const Ibss = 1 << 1;
        const Privacy = 1 << 4;
        const ShortPreamble = 1 << 5;
        const SpectrumManagement = 1 << 8;
        const Qos = 1 << 9;
        const ShortSlotTime = 1 << 10;
        const Apsd = 1 << 11;
        const RadioMeasurement = 1 << 12 ;
        const Epd =  1 << 13;
        const _ = !0;
    }
}

impl<T: AsRef<[u8]> + ?Sized> Parseable<T> for Nl80211BssCapabilities {
    fn parse(buf: &T) -> Result<Self, DecodeError> {
        let buf: &[u8] = buf.as_ref();
        Ok(Self::from_bits_retain(parse_u16(buf).context(format!(
            "Invalid Nl80211BssCapabilities payload {buf:?}"
        ))?))
    }
}

impl Nl80211BssCapabilities {
    pub const LENGTH: usize = 2;
}

impl Emitable for Nl80211BssCapabilities {
    fn buffer_len(&self) -> usize {
        Self::LENGTH
    }

    fn emit(&self, buffer: &mut [u8]) {
        buffer.copy_from_slice(&self.bits().to_ne_bytes())
    }
}

bitflags::bitflags! {
    #[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
    #[non_exhaustive]
    pub struct Nl80211BssUseFor: u32 {
        const Normal = 1 << 0;
        const MldLink = 1 << 1;
        const _ = !0;
    }
}

impl<T: AsRef<[u8]> + ?Sized> Parseable<T> for Nl80211BssUseFor {
    fn parse(buf: &T) -> Result<Self, DecodeError> {
        let buf: &[u8] = buf.as_ref();
        Ok(Self::from_bits_retain(parse_u32(buf).context(format!(
            "Invalid Nl80211BssUseFor payload {buf:?}"
        ))?))
    }
}

impl Nl80211BssUseFor {
    pub const LENGTH: usize = 4;
}

impl Emitable for Nl80211BssUseFor {
    fn buffer_len(&self) -> usize {
        Self::LENGTH
    }

    fn emit(&self, buffer: &mut [u8]) {
        buffer.copy_from_slice(&self.bits().to_ne_bytes())
    }
}

const ETH_ALEN: usize = 6;

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
const NL80211_BSS_LAST_SEEN_BOOTTIME: u16 = 15;
//NL80211_BSS_PAD 16,
//NL80211_BSS_PARENT_TSF 17 ,
//NL80211_BSS_PARENT_BSSID 18,
//NL80211_BSS_CHAIN_SIGNAL 19,
const NL80211_BSS_FREQUENCY_OFFSET: u16 = 20;
//NL80211_BSS_MLO_LINK_ID 21,
//NL80211_BSS_MLD_ADDR 22 ,
const NL80211_BSS_USE_FOR: u16 = 23;
//NL80211_BSS_CANNOT_USE_REASONS 24,

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Nl80211BssInfo {
    Bssid([u8; ETH_ALEN]),
    /// Frequency in MHz
    Frequency(u32),
    /// Timing Synchronization Function (TSF) of received probe response/beacon
    /// in microsecond(μs).
    Tsf(u64),
    /// Beacon interval of the (I)BSS
    BeaconInterval(u16),
    Capability(Nl80211BssCapabilities),
    InformationElements(RawNl80211Elements),
    SignalMbm(i32),
    SignalUnspec(u8),
    Status(u32),
    SeenMsAgo(u32),
    BeaconInformationElements(RawNl80211Elements),
    ChanWidth(u32),
    BeaconTsf(u64),
    ProbeResponseInformationElements(RawNl80211Elements),
    /// `CLOCK_BOOTTIME` timestamp when this entry was last updated by a
    /// received frame. The value is expected to be accurate to about 10ms.
    /// (u64, nanoseconds)
    LastSeenBootTime(u64),
    /// Frequency offset in KHz
    FrequencyOffset(u32),
    UseFor(Nl80211BssUseFor),
    Other(DefaultNla),
}

impl Nla for Nl80211BssInfo {
    fn value_len(&self) -> usize {
        match self {
            Self::Bssid(_) => ETH_ALEN,
            Self::SignalUnspec(_) => 1,
            Self::BeaconInterval(_) => 2,
            Self::Frequency(_)
            | Self::SignalMbm(_)
            | Self::Status(_)
            | Self::SeenMsAgo(_)
            | Self::ChanWidth(_)
            | Self::FrequencyOffset(_) => 4,
            Self::BeaconTsf(_) | Self::Tsf(_) | Self::LastSeenBootTime(_) => 8,
            Self::InformationElements(v)
            | Self::BeaconInformationElements(v)
            | Self::ProbeResponseInformationElements(v) => v.buffer_len(),
            Self::Capability(_) => Nl80211BssCapabilities::LENGTH,
            Self::UseFor(_) => Nl80211BssUseFor::LENGTH,
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Bssid(_) => NL80211_BSS_BSSID,
            Self::Frequency(_) => NL80211_BSS_FREQUENCY,
            Self::Tsf(_) => NL80211_BSS_TSF,
            Self::BeaconInterval(_) => NL80211_BSS_BEACON_INTERVAL,
            Self::InformationElements(_) => NL80211_BSS_INFORMATION_ELEMENTS,
            Self::SignalMbm(_) => NL80211_BSS_SIGNAL_MBM,
            Self::SignalUnspec(_) => NL80211_BSS_SIGNAL_UNSPEC,
            Self::Status(_) => NL80211_BSS_STATUS,
            Self::SeenMsAgo(_) => NL80211_BSS_SEEN_MS_AGO,
            Self::ChanWidth(_) => NL80211_BSS_CHAN_WIDTH,
            Self::BeaconTsf(_) => NL80211_BSS_BEACON_TSF,
            Self::BeaconInformationElements(_) => NL80211_BSS_BEACON_IES,
            Self::Capability(_) => NL80211_BSS_CAPABILITY,
            Self::ProbeResponseInformationElements(_) => NL80211_BSS_PRESP_DATA,
            Self::LastSeenBootTime(_) => NL80211_BSS_LAST_SEEN_BOOTTIME,
            Self::FrequencyOffset(_) => NL80211_BSS_FREQUENCY_OFFSET,
            Self::UseFor(_) => NL80211_BSS_USE_FOR,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Bssid(v) => buffer[..ETH_ALEN].copy_from_slice(v),
            Self::SignalUnspec(d) => buffer[0] = *d,
            Self::BeaconInterval(d) => write_u16(buffer, *d),
            Self::Frequency(d)
            | Self::Status(d)
            | Self::SeenMsAgo(d)
            | Self::ChanWidth(d)
            | Self::FrequencyOffset(d) => write_u32(buffer, *d),
            Self::SignalMbm(d) => write_i32(buffer, *d),
            Self::BeaconTsf(d) | Self::Tsf(d) | Self::LastSeenBootTime(d) => {
                write_u64(buffer, *d)
            }
            Self::InformationElements(v)
            | Self::BeaconInformationElements(v)
            | Self::ProbeResponseInformationElements(v) => v.emit(buffer),
            Self::Capability(v) => v.emit(buffer),
            Self::UseFor(v) => v.emit(buffer),
            Self::Other(ref attr) => attr.emit(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for Nl80211BssInfo
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NL80211_BSS_BSSID => {
                if payload.len() < ETH_ALEN {
                    return Err(format!(
                        "Invalid NL80211_BSS_BSSID {payload:?}"
                    )
                    .into());
                }
                let mut bssid = [0u8; ETH_ALEN];
                bssid.copy_from_slice(&payload[..ETH_ALEN]);
                Self::Bssid(bssid)
            }
            NL80211_BSS_TSF => {
                let err_msg =
                    format!("Invalid NL80211_BSS_TSF value {payload:?}");
                Self::Tsf(parse_u64(payload).context(err_msg)?)
            }
            NL80211_BSS_FREQUENCY => {
                let err_msg =
                    format!("Invalid NL80211_BSS_FREQUENCY value {payload:?}");
                Self::Frequency(parse_u32(payload).context(err_msg)?)
            }
            NL80211_BSS_BEACON_INTERVAL => {
                let err_msg = format!(
                    "Invalid NL80211_BSS_BEACON_INTERVAL value {payload:?}"
                );
                Self::BeaconInterval(parse_u16(payload).context(err_msg)?)
            }
            NL80211_BSS_CAPABILITY => {
                Self::Capability(Nl80211BssCapabilities::parse(payload)?)
            }
            NL80211_BSS_BEACON_IES => Self::BeaconInformationElements(
                RawNl80211Elements::parse(payload)?,
            ),
            NL80211_BSS_INFORMATION_ELEMENTS => {
                Self::InformationElements(RawNl80211Elements::parse(payload)?)
            }
            NL80211_BSS_PRESP_DATA => Self::ProbeResponseInformationElements(
                RawNl80211Elements::parse(payload)?,
            ),
            NL80211_BSS_SIGNAL_MBM => {
                let err_msg =
                    format!("Invalid NL80211_BSS_SIGNAL_MBM value {payload:?}");
                Self::SignalMbm(i32::from_ne_bytes(
                    payload.try_into().context(err_msg)?,
                ))
            }
            NL80211_BSS_SIGNAL_UNSPEC => {
                let err_msg = format!(
                    "Invalid NL80211_BSS_SIGNAL_UNSPEC value {payload:?}"
                );
                Self::SignalUnspec(parse_u8(payload).context(err_msg)?)
            }
            NL80211_BSS_STATUS => {
                let err_msg =
                    format!("Invalid NL80211_BSS_STATUS value {payload:?}");
                Self::Status(parse_u32(payload).context(err_msg)?)
            }
            NL80211_BSS_SEEN_MS_AGO => {
                let err_msg = format!(
                    "Invalid NL80211_BSS_SEEN_MS_AGO value {payload:?}"
                );
                Self::SeenMsAgo(parse_u32(payload).context(err_msg)?)
            }
            NL80211_BSS_CHAN_WIDTH => {
                let err_msg =
                    format!("Invalid NL80211_BSS_CHAN_WIDTH value {payload:?}");
                Self::ChanWidth(parse_u32(payload).context(err_msg)?)
            }
            NL80211_BSS_BEACON_TSF => {
                let err_msg =
                    format!("Invalid NL80211_BSS_BEACON_TSF value {payload:?}");
                Self::BeaconTsf(parse_u64(payload).context(err_msg)?)
            }
            NL80211_BSS_LAST_SEEN_BOOTTIME => {
                let err_msg = format!(
                    "Invalid NL80211_BSS_LAST_SEEN_BOOTTIME value {payload:?}"
                );
                Self::LastSeenBootTime(parse_u64(payload).context(err_msg)?)
            }
            NL80211_BSS_FREQUENCY_OFFSET => {
                Self::FrequencyOffset(parse_u32(payload).context(format!(
                    "Invalid NL80211_BSS_FREQUENCY_OFFSET {payload:?}"
                ))?)
            }
            NL80211_BSS_USE_FOR => {
                Self::UseFor(Nl80211BssUseFor::parse(payload)?)
            }
            _ => Self::Other(
                DefaultNla::parse(buf).context("invalid NLA (unknown kind)")?,
            ),
        })
    }
}
