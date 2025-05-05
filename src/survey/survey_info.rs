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
use std::fmt::Debug;

use anyhow::Context;
use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer},
    parsers::{parse_u32, parse_u64},
    DecodeError, Emitable, Parseable,
};

use crate::bytes::{write_u32, write_u64};

const NL80211_SURVEY_INFO_FREQUENCY: u16 = 1;
const NL80211_SURVEY_INFO_NOISE: u16 = 2;
// const NL80211_SURVEY_INFO_IN_USE: u16 = 3;
const NL80211_SURVEY_INFO_TIME: u16 = 4;
const NL80211_SURVEY_INFO_TIME_BUSY: u16 = 5;
const NL80211_SURVEY_INFO_TIME_EXT_BUSY: u16 = 6;
const NL80211_SURVEY_INFO_TIME_RX: u16 = 7;
const NL80211_SURVEY_INFO_TIME_TX: u16 = 8;
// const NL80211_SURVEY_INFO_TIME_SCAN: u16 = 9;
// const NL80211_SURVEY_INFO_PAD: u16 = 10;
// const NL80211_SURVEY_INFO_TIME_BSS_RX: u16 = 11;
// const NL80211_SURVEY_INFO_FREQUENCY_OFFSET: u16 = 12;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum Nl80211SurveyInfo {
    // Center frequency of channel in MHz
    Frequency(u32),
    /// Noise level of channel (dBm)
    Noise(i8),
    /// Amount of time (in ms) that the radio was turned on (on channel or
    /// globally)
    ActiveTime(u64),
    /// Amount of the time the primary channel was sensed busy (either due to
    /// activity or energy detect)
    BusyTime(u64),
    /// Amount of time the extension channel was sensed busy
    ExtensionBusyTime(u64),
    /// Amount of time the radio spent receiving data (on channel or globally)
    TimeRx(u64),
    /// Amount of time the radio spent transmitting data (on channel or
    /// globally)
    TimeTx(u64),
    Other(DefaultNla),
}

impl Nla for Nl80211SurveyInfo {
    fn value_len(&self) -> usize {
        match self {
            Self::Frequency(v) => std::mem::size_of_val(v),
            Self::Noise(v) => std::mem::size_of_val(v),
            Self::ActiveTime(v)
            | Self::BusyTime(v)
            | Self::ExtensionBusyTime(v)
            | Self::TimeRx(v)
            | Self::TimeTx(v) => std::mem::size_of_val(v),
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Frequency(_) => NL80211_SURVEY_INFO_FREQUENCY,
            Self::Noise(_) => NL80211_SURVEY_INFO_NOISE,
            Self::ActiveTime(_) => NL80211_SURVEY_INFO_TIME,
            Self::BusyTime(_) => NL80211_SURVEY_INFO_TIME_BUSY,
            Self::ExtensionBusyTime(_) => NL80211_SURVEY_INFO_TIME_EXT_BUSY,
            Self::TimeRx(_) => NL80211_SURVEY_INFO_TIME_RX,
            Self::TimeTx(_) => NL80211_SURVEY_INFO_TIME_TX,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        #[allow(clippy::cast_sign_loss)]
        match self {
            Self::Frequency(d) => write_u32(buffer, *d),
            Self::Noise(d) => buffer[0] = *d as u8,
            Self::ActiveTime(d)
            | Self::BusyTime(d)
            | Self::ExtensionBusyTime(d)
            | Self::TimeRx(d)
            | Self::TimeTx(d) => write_u64(buffer, *d),
            Self::Other(ref attr) => attr.emit(buffer),
        }
    }
}

// TODO: Use netlink_packet_utils version, once released.
pub fn parse_i8(payload: &[u8]) -> Result<i8, DecodeError> {
    if payload.len() != 1 {
        return Err(format!("invalid i8: {payload:?}").into());
    }
    #[allow(clippy::cast_possible_wrap)]
    Ok(payload[0] as i8)
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for Nl80211SurveyInfo
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NL80211_SURVEY_INFO_FREQUENCY => {
                let err_msg = format!(
                    "Invalid NL80211_SURVEY_INFO_FREQUENCY value {payload:?}"
                );
                Self::Frequency(parse_u32(payload).context(err_msg)?)
            }
            NL80211_SURVEY_INFO_NOISE => {
                let err_msg = format!(
                    "Invalid NL80211_SURVEY_INFO_NOISE value {payload:?}"
                );
                // In kernel level, this is treated as a u8, but `iw` and the
                // real word treat this as a two's complement
                // 8bit singed integer.
                Self::Noise(parse_i8(payload).context(err_msg)?)
            }
            NL80211_SURVEY_INFO_TIME => {
                let err_msg = format!(
                    "Invalid {} value {payload:?}",
                    stringify!(NL80211_SURVEY_INFO_TIME),
                );
                Self::ActiveTime(parse_u64(payload).context(err_msg)?)
            }
            NL80211_SURVEY_INFO_TIME_BUSY => {
                let err_msg = format!(
                    "Invalid {} value {payload:?}",
                    stringify!(NL80211_SURVEY_INFO_TIME_BUSY),
                );
                Self::ExtensionBusyTime(parse_u64(payload).context(err_msg)?)
            }
            NL80211_SURVEY_INFO_TIME_EXT_BUSY => {
                let err_msg = format!(
                    "Invalid {} value {payload:?}",
                    stringify!(NL80211_SURVEY_INFO_TIME_EXT_BUSY),
                );
                Self::ExtensionBusyTime(parse_u64(payload).context(err_msg)?)
            }
            NL80211_SURVEY_INFO_TIME_RX => {
                let err_msg = format!(
                    "Invalid {} value {payload:?}",
                    stringify!(NL80211_SURVEY_INFO_TIME_RX),
                );
                Self::TimeTx(parse_u64(payload).context(err_msg)?)
            }
            NL80211_SURVEY_INFO_TIME_TX => {
                let err_msg = format!(
                    "Invalid {} value {payload:?}",
                    stringify!(NL80211_SURVEY_INFO_TIME_TX),
                );
                Self::TimeRx(parse_u64(payload).context(err_msg)?)
            }
            _ => Self::Other(
                DefaultNla::parse(buf).context("invalid NLA (unknown kind)")?,
            ),
        })
    }
}
