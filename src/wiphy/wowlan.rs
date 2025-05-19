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

use anyhow::Context;
use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer, NlasIterator},
    parsers::parse_u32,
    DecodeError, Emitable, Parseable,
};

use crate::bytes::write_u32;

const NL80211_WOWLAN_TRIG_ANY: u16 = 1;
const NL80211_WOWLAN_TRIG_DISCONNECT: u16 = 2;
const NL80211_WOWLAN_TRIG_MAGIC_PKT: u16 = 3;
const NL80211_WOWLAN_TRIG_PKT_PATTERN: u16 = 4;
const NL80211_WOWLAN_TRIG_GTK_REKEY_SUPPORTED: u16 = 5;
const NL80211_WOWLAN_TRIG_GTK_REKEY_FAILURE: u16 = 6;
const NL80211_WOWLAN_TRIG_EAP_IDENT_REQUEST: u16 = 7;
const NL80211_WOWLAN_TRIG_4WAY_HANDSHAKE: u16 = 8;
const NL80211_WOWLAN_TRIG_RFKILL_RELEASE: u16 = 9;
// const NL80211_WOWLAN_TRIG_WAKEUP_PKT_80211: u16 = 10;
// const NL80211_WOWLAN_TRIG_WAKEUP_PKT_80211_LEN: u16 = 11;
// const NL80211_WOWLAN_TRIG_WAKEUP_PKT_8023: u16 = 12;
// const NL80211_WOWLAN_TRIG_WAKEUP_PKT_8023_LEN: u16 = 13;
const NL80211_WOWLAN_TRIG_TCP_CONNECTION: u16 = 14;
// const NL80211_WOWLAN_TRIG_WAKEUP_TCP_MATCH: u16 = 15;
// const NL80211_WOWLAN_TRIG_WAKEUP_TCP_CONNLOST: u16 = 16;
// const NL80211_WOWLAN_TRIG_WAKEUP_TCP_NOMORETOKENS: u16 = 17;
const NL80211_WOWLAN_TRIG_NET_DETECT: u16 = 18;
// const NL80211_WOWLAN_TRIG_NET_DETECT_RESULTS: u16 = 19;
// const NL80211_WOWLAN_TRIG_UNPROTECTED_DEAUTH_DISASSOC: u16 = 20;

/// Supported WoWLAN trigger
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Nl80211WowlanTriggersSupport {
    /// Wake up on any activity, do not really put the chip into a special
    /// state -- works best with chips that have support for low-power
    /// operation already.
    /// Note that this mode is incompatible with all of the others, if
    /// any others are even supported by the device.
    Any,
    /// Wake up on disconnect, the way disconnect is detected is
    /// implementation-specific.
    Disconnect,
    /// Wake up on magic packet (6x 0xff, followed by 16 repetitions of MAC
    /// addr, anywhere in payload).
    MagicPkt,
    /// Wake up on the specified packet patterns.
    /// The matching is done on the MSDU, i.e.  as though the packet was an
    /// 802.3 packet, so the pattern matching is done after the packet is
    /// converted to the MSDU.
    PktPattern(Nl80211WowlanTriggerPatternSupport),
    /// Not a real trigger, and cannot be used when setting, used only to
    /// indicate that GTK rekeying is supported by the device.
    GtkRekeySupported,
    /// wake up on GTK rekey failure (if done by the device).
    GtkRekeyFailure,
    /// wake up on EAP Identity Request packet.
    EapIdentRequest,
    /// wake up on 4-way handshake.
    FourWayHandshake,
    /// wake up when rfkill is released (on devices that have rfkill in the
    /// device).
    RfkillRelease,
    /// The number of match sets supported by driver for waking up when a
    /// configured network is detected.
    NetDetect(u32),
    /// TCP connection wake.
    TcpConnection(Vec<Nl80211WowlanTcpTriggerSupport>),
    Other(DefaultNla),
}

impl Nla for Nl80211WowlanTriggersSupport {
    fn value_len(&self) -> usize {
        match self {
            Self::Any
            | Self::Disconnect
            | Self::MagicPkt
            | Self::GtkRekeySupported
            | Self::GtkRekeyFailure
            | Self::EapIdentRequest
            | Self::FourWayHandshake
            | Self::RfkillRelease => 0,
            Self::PktPattern(_) => Nl80211WowlanTriggerPatternSupport::LENGTH,
            Self::NetDetect(_) => 4,
            Self::TcpConnection(s) => s.as_slice().buffer_len(),
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Any => NL80211_WOWLAN_TRIG_ANY,
            Self::Disconnect => NL80211_WOWLAN_TRIG_DISCONNECT,
            Self::MagicPkt => NL80211_WOWLAN_TRIG_MAGIC_PKT,
            Self::GtkRekeySupported => NL80211_WOWLAN_TRIG_GTK_REKEY_SUPPORTED,
            Self::GtkRekeyFailure => NL80211_WOWLAN_TRIG_GTK_REKEY_FAILURE,
            Self::EapIdentRequest => NL80211_WOWLAN_TRIG_EAP_IDENT_REQUEST,
            Self::FourWayHandshake => NL80211_WOWLAN_TRIG_4WAY_HANDSHAKE,
            Self::RfkillRelease => NL80211_WOWLAN_TRIG_RFKILL_RELEASE,
            Self::PktPattern(_) => NL80211_WOWLAN_TRIG_PKT_PATTERN,
            Self::NetDetect(_) => NL80211_WOWLAN_TRIG_NET_DETECT,
            Self::TcpConnection(_) => NL80211_WOWLAN_TRIG_TCP_CONNECTION,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Any
            | Self::Disconnect
            | Self::MagicPkt
            | Self::GtkRekeySupported
            | Self::GtkRekeyFailure
            | Self::EapIdentRequest
            | Self::FourWayHandshake
            | Self::RfkillRelease => (),
            Self::PktPattern(s) => s.emit(buffer),
            Self::NetDetect(d) => write_u32(buffer, *d),
            Self::TcpConnection(s) => s.as_slice().emit(buffer),
            Self::Other(attr) => attr.emit(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for Nl80211WowlanTriggersSupport
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NL80211_WOWLAN_TRIG_ANY => Self::Any,
            NL80211_WOWLAN_TRIG_DISCONNECT => Self::Disconnect,
            NL80211_WOWLAN_TRIG_MAGIC_PKT => Self::MagicPkt,
            NL80211_WOWLAN_TRIG_GTK_REKEY_SUPPORTED => Self::GtkRekeySupported,
            NL80211_WOWLAN_TRIG_GTK_REKEY_FAILURE => Self::GtkRekeyFailure,
            NL80211_WOWLAN_TRIG_EAP_IDENT_REQUEST => Self::EapIdentRequest,
            NL80211_WOWLAN_TRIG_4WAY_HANDSHAKE => Self::FourWayHandshake,
            NL80211_WOWLAN_TRIG_RFKILL_RELEASE => Self::RfkillRelease,
            NL80211_WOWLAN_TRIG_PKT_PATTERN => Self::PktPattern(
                Nl80211WowlanTriggerPatternSupport::parse(payload)?,
            ),
            NL80211_WOWLAN_TRIG_NET_DETECT => {
                Self::NetDetect(parse_u32(payload).context(format!(
                    "Invalid NL80211_WOWLAN_TRIG_NET_DETECT \
                            {payload:?}"
                ))?)
            }
            NL80211_WOWLAN_TRIG_TCP_CONNECTION => {
                let mut nlas = Vec::new();
                for nla in NlasIterator::new(payload) {
                    let err_msg = format!(
                        "Invalid NL80211_WOWLAN_TRIG_TCP_CONNECTION value {nla:?}"
                    );
                    let nla = &nla.context(err_msg.clone())?;
                    nlas.push(Nl80211WowlanTcpTriggerSupport::parse(nla)?);
                }

                Self::TcpConnection(nlas)
            }
            _ => Self::Other(DefaultNla::parse(buf).context(
                "invalid NLA for NL80211_ATTR_WOWLAN_TRIGGERS_SUPPORTED ",
            )?),
        })
    }
}

/// Support status of WoWLAN trigger pattern
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Nl80211WowlanTriggerPatternSupport {
    pub max_patterns: u32,
    pub min_pattern_len: u32,
    pub max_pattern_len: u32,
    pub max_pkt_offset: u32,
}

impl Nl80211WowlanTriggerPatternSupport {
    const LENGTH: usize = 16;

    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        if payload.len() < Self::LENGTH {
            Err(format!(
                "Invalid NL80211_WOWLAN_TRIG_PKT_PATTERN \
                for support query, expecting length {} but got {}: \
                {payload:?}",
                Self::LENGTH,
                payload.len()
            )
            .into())
        } else {
            Ok(Self {
                max_patterns: parse_u32(&payload[..4])?,
                min_pattern_len: parse_u32(&payload[4..8])?,
                max_pattern_len: parse_u32(&payload[8..12])?,
                max_pkt_offset: parse_u32(&payload[12..16])?,
            })
        }
    }
}

impl Emitable for Nl80211WowlanTriggerPatternSupport {
    fn buffer_len(&self) -> usize {
        Self::LENGTH
    }

    fn emit(&self, buffer: &mut [u8]) {
        write_u32(&mut buffer[0..4], self.max_patterns);
        write_u32(&mut buffer[4..8], self.min_pattern_len);
        write_u32(&mut buffer[8..12], self.max_pattern_len);
        write_u32(&mut buffer[12..16], self.max_pkt_offset);
    }
}

const NL80211_WOWLAN_TCP_SRC_IPV4: u16 = 1;
const NL80211_WOWLAN_TCP_DST_IPV4: u16 = 2;
const NL80211_WOWLAN_TCP_DST_MAC: u16 = 3;
const NL80211_WOWLAN_TCP_SRC_PORT: u16 = 4;
const NL80211_WOWLAN_TCP_DST_PORT: u16 = 5;
const NL80211_WOWLAN_TCP_DATA_PAYLOAD: u16 = 6;
const NL80211_WOWLAN_TCP_DATA_PAYLOAD_SEQ: u16 = 7;
const NL80211_WOWLAN_TCP_DATA_PAYLOAD_TOKEN: u16 = 8;
const NL80211_WOWLAN_TCP_DATA_INTERVAL: u16 = 9;
const NL80211_WOWLAN_TCP_WAKE_PAYLOAD: u16 = 10;
const NL80211_WOWLAN_TCP_WAKE_MASK: u16 = 11;

/// Supported WoWLAN TCP connection trigger
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Nl80211WowlanTcpTriggerSupport {
    SrcIpv4,
    DstIpv4,
    DstMac,
    SrcPort,
    DstPort,
    DataPayload(u32),
    DataPayloadSeq,
    DataPayloadToken,
    DataInterval(u32),
    WakePayload(u32),
    WakeMask,
    Other(DefaultNla),
}

impl Nla for Nl80211WowlanTcpTriggerSupport {
    fn value_len(&self) -> usize {
        match self {
            Self::SrcIpv4
            | Self::DstIpv4
            | Self::DstMac
            | Self::SrcPort
            | Self::DstPort
            | Self::DataPayloadSeq
            | Self::DataPayloadToken
            | Self::WakeMask => 0,
            Self::DataPayload(_)
            | Self::DataInterval(_)
            | Self::WakePayload(_) => 4,
            Self::Other(v) => v.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::SrcIpv4 => NL80211_WOWLAN_TCP_SRC_IPV4,
            Self::DstIpv4 => NL80211_WOWLAN_TCP_DST_IPV4,
            Self::DstMac => NL80211_WOWLAN_TCP_DST_MAC,
            Self::SrcPort => NL80211_WOWLAN_TCP_SRC_PORT,
            Self::DstPort => NL80211_WOWLAN_TCP_DST_PORT,
            Self::DataPayload(_) => NL80211_WOWLAN_TCP_DATA_PAYLOAD,
            Self::DataPayloadSeq => NL80211_WOWLAN_TCP_DATA_PAYLOAD_SEQ,
            Self::DataPayloadToken => NL80211_WOWLAN_TCP_DATA_PAYLOAD_TOKEN,
            Self::DataInterval(_) => NL80211_WOWLAN_TCP_DATA_INTERVAL,
            Self::WakePayload(_) => NL80211_WOWLAN_TCP_WAKE_PAYLOAD,
            Self::WakeMask => NL80211_WOWLAN_TCP_WAKE_MASK,
            Self::Other(v) => v.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::SrcIpv4
            | Self::DstIpv4
            | Self::DstMac
            | Self::SrcPort
            | Self::DstPort
            | Self::DataPayloadSeq
            | Self::DataPayloadToken
            | Self::WakeMask => (),
            Self::DataPayload(d)
            | Self::DataInterval(d)
            | Self::WakePayload(d) => write_u32(buffer, *d),
            Self::Other(v) => v.emit(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for Nl80211WowlanTcpTriggerSupport
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NL80211_WOWLAN_TCP_SRC_IPV4 => Self::SrcIpv4,
            NL80211_WOWLAN_TCP_DST_IPV4 => Self::DstIpv4,
            NL80211_WOWLAN_TCP_DST_MAC => Self::DstMac,
            NL80211_WOWLAN_TCP_SRC_PORT => Self::SrcPort,
            NL80211_WOWLAN_TCP_DST_PORT => Self::DstPort,
            NL80211_WOWLAN_TCP_DATA_PAYLOAD => {
                Self::DataPayload(parse_u32(payload).context(format!(
                    "Invalid NL80211_WOWLAN_TCP_DATA_PAYLOAD {payload:?}"
                ))?)
            }
            NL80211_WOWLAN_TCP_DATA_PAYLOAD_SEQ => Self::DataPayloadSeq,
            NL80211_WOWLAN_TCP_DATA_PAYLOAD_TOKEN => Self::DataPayloadToken,
            NL80211_WOWLAN_TCP_DATA_INTERVAL => {
                Self::DataInterval(parse_u32(payload).context(format!(
                    "Invalid NL80211_WOWLAN_TCP_DATA_INTERVAL {payload:?}"
                ))?)
            }
            NL80211_WOWLAN_TCP_WAKE_PAYLOAD => {
                Self::WakePayload(parse_u32(payload).context(format!(
                    "Invalid NL80211_WOWLAN_TCP_WAKE_PAYLOAD {payload:?}"
                ))?)
            }
            NL80211_WOWLAN_TCP_WAKE_MASK => Self::WakeMask,
            _ => Self::Other(
                DefaultNla::parse(buf).context("invalid NLA (unknown kind)")?,
            ),
        })
    }
}
