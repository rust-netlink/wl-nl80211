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
 * Copyright 2015-2017 Intel Deutschland GmbH
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

use futures::TryStream;
use netlink_packet_core::{
    parse_i32, parse_u32, DecodeError, DefaultNla, ErrorContext, Nla,
    NlaBuffer, NlasIterator, Parseable, NLM_F_ACK, NLM_F_REQUEST,
};
use netlink_packet_generic::GenlMessage;

use crate::mac::ETH_ALEN;
use crate::{
    bytes::write_i32, bytes::write_u32, nl80211_execute, Nl80211Attr,
    Nl80211Command, Nl80211Error, Nl80211Handle, Nl80211Message,
};

// NL80211_ATTR_CQM nested sub-attribute ids (enum nl80211_attr_cqm).
const NL80211_ATTR_CQM_RSSI_THOLD: u16 = 1;
const NL80211_ATTR_CQM_RSSI_HYST: u16 = 2;
const NL80211_ATTR_CQM_RSSI_THRESHOLD_EVENT: u16 = 3;
// const NL80211_ATTR_CQM_PKT_LOSS_EVENT: u16 = 4;
// const NL80211_ATTR_CQM_TXE_RATE: u16 = 5;
// const NL80211_ATTR_CQM_TXE_PKTS: u16 = 6;
// const NL80211_ATTR_CQM_TXE_INTVL: u16 = 7;
// const NL80211_ATTR_CQM_BEACON_LOSS_EVENT: u16 = 8;
const NL80211_ATTR_CQM_RSSI_LEVEL: u16 = 9;

/// RSSI threshold crossing direction of a `NL80211_CMD_NOTIFY_CQM` event
/// (enum nl80211_cqm_rssi_threshold_event).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Nl80211CqmRssiThresholdEvent {
    /// The RSSI level is lower than the configured threshold.
    Low,
    /// The RSSI is higher than the configured threshold.
    High,
    /// Unknown / future kernel event value.
    Other(u32),
}

impl From<u32> for Nl80211CqmRssiThresholdEvent {
    fn from(v: u32) -> Self {
        match v {
            0 => Self::Low,
            1 => Self::High,
            other => Self::Other(other),
        }
    }
}

impl From<Nl80211CqmRssiThresholdEvent> for u32 {
    fn from(v: Nl80211CqmRssiThresholdEvent) -> Self {
        match v {
            Nl80211CqmRssiThresholdEvent::Low => 0,
            Nl80211CqmRssiThresholdEvent::High => 1,
            Nl80211CqmRssiThresholdEvent::Other(v) => v,
        }
    }
}

/// A `NL80211_CMD_NOTIFY_CQM` event reported by the kernel: the
/// `NL80211_ATTR_WIPHY` / `NL80211_ATTR_IFINDEX` of the reporting
/// interface, the peer MAC (`NL80211_ATTR_MAC`, when the kernel included
/// it) and the full list of `NL80211_ATTR_CQM` sub-attributes.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Nl80211CqmRssiEvent {
    /// `NL80211_ATTR_WIPHY`: the wiphy index of the reporting interface.
    pub wiphy: u32,
    /// `NL80211_ATTR_IFINDEX`: the interface index.
    pub if_index: u32,
    /// `NL80211_ATTR_MAC`: the peer MAC, when the kernel included it.
    pub mac: Option<[u8; ETH_ALEN]>,
    /// The nested `NL80211_ATTR_CQM` sub-attributes (`RssiThresholdEvent`,
    /// `RssiLevel`, ...).
    pub events: Vec<Nl80211CqmAttr>,
}

/// Sub-attribute of the nested `NL80211_ATTR_CQM` attribute
/// (`NL80211_CMD_SET_CQM` / `NL80211_CMD_NOTIFY_CQM`).
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Nl80211CqmAttr {
    /// `NL80211_ATTR_CQM_RSSI_THOLD`: RSSI threshold in dBm. The kernel
    /// reports a `NL80211_CMD_NOTIFY_CQM` event when the measured RSSI
    /// crosses it. Negative value `0` disables RSSI monitoring.
    RssiThold(i32),
    /// `NL80211_ATTR_CQM_RSSI_HYST`: RSSI hysteresis in dBm, the kernel
    /// re-arms the opposite event only after the signal moved past the
    /// threshold by this amount.
    RssiHyst(u32),
    /// `NL80211_ATTR_CQM_RSSI_THRESHOLD_EVENT`: which threshold was
    /// crossed in a `NL80211_CMD_NOTIFY_CQM` event.
    RssiThresholdEvent(Nl80211CqmRssiThresholdEvent),
    /// `NL80211_ATTR_CQM_RSSI_LEVEL`: the RSSI value in dBm that
    /// triggered a `NL80211_CMD_NOTIFY_CQM` event.
    RssiLevel(i32),
    /// Unknown / unmodelled sub-attribute.
    Other(DefaultNla),
}

impl Nla for Nl80211CqmAttr {
    fn value_len(&self) -> usize {
        match self {
            Self::RssiThold(_)
            | Self::RssiHyst(_)
            | Self::RssiThresholdEvent(_)
            | Self::RssiLevel(_) => 4,
            Self::Other(v) => v.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::RssiThold(_) => NL80211_ATTR_CQM_RSSI_THOLD,
            Self::RssiHyst(_) => NL80211_ATTR_CQM_RSSI_HYST,
            Self::RssiThresholdEvent(_) => {
                NL80211_ATTR_CQM_RSSI_THRESHOLD_EVENT
            }
            Self::RssiLevel(_) => NL80211_ATTR_CQM_RSSI_LEVEL,
            Self::Other(v) => v.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::RssiThold(d) => write_i32(buffer, *d),
            Self::RssiHyst(d) => write_u32(buffer, *d),
            Self::RssiThresholdEvent(d) => write_u32(buffer, u32::from(*d)),
            Self::RssiLevel(d) => write_i32(buffer, *d),
            Self::Other(v) => v.emit_value(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for Nl80211CqmAttr
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NL80211_ATTR_CQM_RSSI_THOLD => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_CQM_RSSI_THOLD value {payload:?}"
                );
                Self::RssiThold(parse_i32(payload).context(err_msg)?)
            }
            NL80211_ATTR_CQM_RSSI_HYST => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_CQM_RSSI_HYST value {payload:?}"
                );
                Self::RssiHyst(parse_u32(payload).context(err_msg)?)
            }
            NL80211_ATTR_CQM_RSSI_THRESHOLD_EVENT => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_CQM_RSSI_THRESHOLD_EVENT value \
                    {payload:?}"
                );
                Self::RssiThresholdEvent(
                    parse_u32(payload).context(err_msg)?.into(),
                )
            }
            NL80211_ATTR_CQM_RSSI_LEVEL => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_CQM_RSSI_LEVEL value {payload:?}"
                );
                Self::RssiLevel(parse_i32(payload).context(err_msg)?)
            }
            _ => Self::Other(
                DefaultNla::parse(buf).context("invalid NLA (unknown kind)")?,
            ),
        })
    }
}

impl Nl80211CqmAttr {
    pub(crate) fn parse_list(
        payload: &[u8],
    ) -> Result<Vec<Nl80211CqmAttr>, DecodeError> {
        let mut attrs = Vec::new();
        for nla in NlasIterator::new(payload) {
            let nla = &nla.context("invalid NL80211_ATTR_CQM")?;
            attrs.push(Nl80211CqmAttr::parse(nla)?);
        }
        Ok(attrs)
    }
}

/// Helper to build the attribute list for a `NL80211_CMD_SET_CQM` request,
/// arming the kernel's connection quality monitor (RSSI threshold crossing
/// notifications, `NL80211_CMD_NOTIFY_CQM` events).
///
/// The kernel measures the connected AP's RSSI (typically from beacons)
/// and emits a `NL80211_CQM_RSSI_THRESHOLD_EVENT` when it crosses the
/// threshold. Drivers without CQM support (e.g. some beacon-filtering
/// mac80211 radios) reply `-EOPNOTSUPP`.
#[derive(Debug)]
pub struct Nl80211Cqm;

impl Nl80211Cqm {
    /// Start building a `NL80211_CMD_SET_CQM` request for `if_index`.
    #[allow(clippy::new_ret_no_self)]
    pub fn new(if_index: u32) -> Nl80211CqmRequestBuilder {
        Nl80211CqmRequestBuilder {
            if_index,
            rssi_thold: None,
            rssi_hyst: None,
        }
    }
}

/// Builder for the attributes of a `NL80211_CMD_SET_CQM` request.
#[derive(Debug)]
pub struct Nl80211CqmRequestBuilder {
    if_index: u32,
    rssi_thold: Option<i32>,
    rssi_hyst: Option<u32>,
}

impl Nl80211CqmRequestBuilder {
    /// The RSSI threshold in dBm below which the kernel reports a LOW
    /// `NL80211_CMD_NOTIFY_CQM` event.
    pub fn rssi_thold(mut self, thold: i32) -> Self {
        self.rssi_thold = Some(thold);
        self
    }

    /// The RSSI hysteresis in dBm; the kernel only reports the HIGH
    /// (recovered) event after the signal moved this far above the
    /// threshold.
    pub fn rssi_hyst(mut self, hyst: u32) -> Self {
        self.rssi_hyst = Some(hyst);
        self
    }

    /// Build the attribute list for a `NL80211_CMD_SET_CQM` request.
    pub fn build(self) -> Vec<Nl80211Attr> {
        let mut cqm = Vec::new();
        if let Some(thold) = self.rssi_thold {
            cqm.push(Nl80211CqmAttr::RssiThold(thold));
        }
        if let Some(hyst) = self.rssi_hyst {
            cqm.push(Nl80211CqmAttr::RssiHyst(hyst));
        }
        vec![Nl80211Attr::IfIndex(self.if_index), Nl80211Attr::Cqm(cqm)]
    }
}

/// Sends a `NL80211_CMD_SET_CQM` request.
pub struct Nl80211CqmRequest {
    handle: Nl80211Handle,
    attributes: Vec<Nl80211Attr>,
}

impl Nl80211CqmRequest {
    pub(crate) fn new(
        handle: Nl80211Handle,
        attributes: Vec<Nl80211Attr>,
    ) -> Self {
        Nl80211CqmRequest { handle, attributes }
    }

    /// Send the `NL80211_CMD_SET_CQM` request.
    ///
    /// A successful return only means the request was accepted by the
    /// kernel; unsupported drivers reply with a netlink error
    /// (`-EOPNOTSUPP`).
    pub async fn execute(
        self,
    ) -> impl TryStream<Ok = GenlMessage<Nl80211Message>, Error = Nl80211Error>
    {
        let Nl80211CqmRequest {
            mut handle,
            attributes,
        } = self;
        let nl80211_msg = Nl80211Message {
            cmd: Nl80211Command::SetCqm,
            attributes,
        };
        nl80211_execute(&mut handle, nl80211_msg, NLM_F_REQUEST | NLM_F_ACK)
            .await
    }
}
