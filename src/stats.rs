// SPDX-License-Identifier: MIT

use anyhow::Context;
use byteorder::{ByteOrder, NativeEndian};
use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer, NlasIterator},
    parsers::{parse_u32, parse_u64},
    DecodeError, Emitable, Parseable,
};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NestedNl80211TidStats(Vec<Nl80211TidStats>);

impl Nla for NestedNl80211TidStats {
    fn value_len(&self) -> usize {
        self.0.as_slice().buffer_len()
    }

    fn kind(&self) -> u16 {
        unimplemented!("Variable between 0-16")
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        self.0.as_slice().emit(buffer);
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for NestedNl80211TidStats
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        let err_msg =
            format!("Invalid NestedNl80211TidStats value {payload:?}");
        let mut nlas = Vec::new();

        for nla in NlasIterator::new(payload) {
            let nla = &nla.context(err_msg.clone())?;
            nlas.push(Nl80211TidStats::parse(nla).context(err_msg.clone())?);
        }
        Ok(Self(nlas))
    }
}

const NL80211_TID_STATS_RX_MSDU: u16 = 1;
const NL80211_TID_STATS_TX_MSDU: u16 = 2;
const NL80211_TID_STATS_TX_MSDU_RETRIES: u16 = 3;
const NL80211_TID_STATS_TX_MSDU_FAILED: u16 = 4;
const NL80211_TID_STATS_TXQ_STATS: u16 = 6;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Nl80211TidStats {
    /// Number of MSDUs received
    RxMsdu(u64),
    /// Number of MSDUs transmitted
    TxMsdu(u64),
    /// Number of retries for transmitted MSDUs (not counting the first
    /// attempt)
    TxMsduRetries(u64),
    /// Number of failed transmitted MSDUs
    TxMsduFailed(u64),
    TransmitQueueStats(Vec<Nl80211TransmitQueueStat>),

    Other(DefaultNla),
}

impl Nla for Nl80211TidStats {
    fn value_len(&self) -> usize {
        match self {
            Self::RxMsdu(_)
            | Self::TxMsdu(_)
            | Self::TxMsduRetries(_)
            | Self::TxMsduFailed(_) => 4,
            Self::TransmitQueueStats(nlas) => nlas.as_slice().buffer_len(),
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::RxMsdu(_) => NL80211_TID_STATS_RX_MSDU,
            Self::TxMsdu(_) => NL80211_TID_STATS_TX_MSDU,
            Self::TxMsduRetries(_) => NL80211_TID_STATS_TX_MSDU_RETRIES,
            Self::TxMsduFailed(_) => NL80211_TID_STATS_TX_MSDU_FAILED,
            Self::TransmitQueueStats(_) => NL80211_TID_STATS_TXQ_STATS,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::RxMsdu(d)
            | Self::TxMsdu(d)
            | Self::TxMsduRetries(d)
            | Self::TxMsduFailed(d) => NativeEndian::write_u64(buffer, *d),
            Self::TransmitQueueStats(nlas) => nlas.as_slice().emit(buffer),
            Self::Other(attr) => attr.emit(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for Nl80211TidStats
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NL80211_TID_STATS_RX_MSDU => {
                let err_msg = format!(
                    "Invalid NL80211_TID_STATS_RX_MSDU value: {payload:?}"
                );
                Self::RxMsdu(parse_u64(payload).context(err_msg)?)
            }
            NL80211_TID_STATS_TX_MSDU => {
                let err_msg = format!(
                    "Invalid NL80211_TID_STATS_TX_MSDU value: {payload:?}"
                );
                Self::TxMsdu(parse_u64(payload).context(err_msg)?)
            }
            NL80211_TID_STATS_TX_MSDU_RETRIES => {
                let err_msg = format!(
                    "Invalid NL80211_TID_STATS_TX_MSDU_RETRIES value: {payload:?}"
                );
                Self::TxMsduRetries(parse_u64(payload).context(err_msg)?)
            }
            NL80211_TID_STATS_TX_MSDU_FAILED => {
                let err_msg = format!(
                    "Invalid NL80211_TID_STATS_TX_MSDU_FAILED value: {payload:?}"
                );
                Self::TxMsduFailed(parse_u64(payload).context(err_msg)?)
            }
            NL80211_TID_STATS_TXQ_STATS => {
                let err_msg = format!(
                    "Invalid NL80211_TID_STATS_TXQ_STATS value {payload:?}"
                );
                let mut nlas = Vec::new();
                for nla in NlasIterator::new(payload) {
                    let nla = &nla.context(err_msg.clone())?;
                    nlas.push(
                        Nl80211TransmitQueueStat::parse(nla)
                            .context(err_msg.clone())?,
                    );
                }
                Self::TransmitQueueStats(nlas)
            }
            _ => Self::Other(
                DefaultNla::parse(buf).context("invalid NLA (unknown kind)")?,
            ),
        })
    }
}

const NL80211_TXQ_STATS_BACKLOG_BYTES: u16 = 1;
const NL80211_TXQ_STATS_BACKLOG_PACKETS: u16 = 2;
const NL80211_TXQ_STATS_FLOWS: u16 = 3;
const NL80211_TXQ_STATS_DROPS: u16 = 4;
const NL80211_TXQ_STATS_ECN_MARKS: u16 = 5;
const NL80211_TXQ_STATS_OVERLIMIT: u16 = 6;
const NL80211_TXQ_STATS_OVERMEMORY: u16 = 7;
const NL80211_TXQ_STATS_COLLISIONS: u16 = 8;
const NL80211_TXQ_STATS_TX_BYTES: u16 = 9;
const NL80211_TXQ_STATS_TX_PACKETS: u16 = 10;
const NL80211_TXQ_STATS_MAX_FLOWS: u16 = 11;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Nl80211TransmitQueueStat {
    BacklogBytes(u32),
    BacklogPackets(u32),
    Flows(u32),
    Drops(u32),
    EcnMarks(u32),
    Overlimit(u32),
    Overmemory(u32),
    Collisions(u32),
    TxBytes(u32),
    TxPackets(u32),
    MaxFlows(u32),
    Other(DefaultNla),
}

impl Nla for Nl80211TransmitQueueStat {
    fn value_len(&self) -> usize {
        match self {
            Self::BacklogBytes(_)
            | Self::BacklogPackets(_)
            | Self::Flows(_)
            | Self::Drops(_)
            | Self::EcnMarks(_)
            | Self::Overlimit(_)
            | Self::Overmemory(_)
            | Self::Collisions(_)
            | Self::TxBytes(_)
            | Self::TxPackets(_)
            | Self::MaxFlows(_) => 4,
            Self::Other(attr) => attr.value_len(),
        }
    }
    fn kind(&self) -> u16 {
        match self {
            Self::BacklogBytes(_) => NL80211_TXQ_STATS_BACKLOG_BYTES,
            Self::BacklogPackets(_) => NL80211_TXQ_STATS_BACKLOG_PACKETS,
            Self::Flows(_) => NL80211_TXQ_STATS_FLOWS,
            Self::Drops(_) => NL80211_TXQ_STATS_DROPS,
            Self::EcnMarks(_) => NL80211_TXQ_STATS_ECN_MARKS,
            Self::Overlimit(_) => NL80211_TXQ_STATS_OVERLIMIT,
            Self::Overmemory(_) => NL80211_TXQ_STATS_OVERMEMORY,
            Self::Collisions(_) => NL80211_TXQ_STATS_COLLISIONS,
            Self::TxBytes(_) => NL80211_TXQ_STATS_TX_BYTES,
            Self::TxPackets(_) => NL80211_TXQ_STATS_TX_PACKETS,
            Self::MaxFlows(_) => NL80211_TXQ_STATS_MAX_FLOWS,
            Self::Other(attr) => attr.kind(),
        }
    }
    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::BacklogBytes(d)
            | Self::BacklogPackets(d)
            | Self::Flows(d)
            | Self::Drops(d)
            | Self::EcnMarks(d)
            | Self::Overlimit(d)
            | Self::Overmemory(d)
            | Self::Collisions(d)
            | Self::TxBytes(d)
            | Self::TxPackets(d)
            | Self::MaxFlows(d) => NativeEndian::write_u32(buffer, *d),
            Self::Other(attr) => attr.emit(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for Nl80211TransmitQueueStat
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NL80211_TXQ_STATS_BACKLOG_BYTES => {
                let err_msg = format!(
                    "Invalid NL80211_TXQ_STATS_BACKLOG_BYTES value {payload:?}"
                );
                Self::BacklogBytes(parse_u32(payload).context(err_msg)?)
            }
            NL80211_TXQ_STATS_BACKLOG_PACKETS => {
                let err_msg = format!(
                    "Invalid NL80211_TXQ_STATS_BACKLOG_PACKETS value: {payload:?}"
                );
                Self::BacklogPackets(parse_u32(payload).context(err_msg)?)
            }
            NL80211_TXQ_STATS_FLOWS => {
                let err_msg = format!(
                    "Invalid NL80211_TXQ_STATS_FLOWS value: {payload:?}"
                );
                Self::Flows(parse_u32(payload).context(err_msg)?)
            }
            NL80211_TXQ_STATS_DROPS => {
                let err_msg = format!(
                    "Invalid NL80211_TXQ_STATS_DROPS value: {payload:?}"
                );
                Self::Drops(parse_u32(payload).context(err_msg)?)
            }
            NL80211_TXQ_STATS_ECN_MARKS => {
                let err_msg = format!(
                    "Invalid NL80211_TXQ_STATS_ECN_MARKS value: {payload:?}"
                );
                Self::EcnMarks(parse_u32(payload).context(err_msg)?)
            }
            NL80211_TXQ_STATS_OVERLIMIT => {
                let err_msg = format!(
                    "Invalid NL80211_TXQ_STATS_OVERLIMIT value: {payload:?}"
                );
                Self::Overlimit(parse_u32(payload).context(err_msg)?)
            }
            NL80211_TXQ_STATS_OVERMEMORY => {
                let err_msg = format!(
                    "Invalid NL80211_TXQ_STATS_OVERMEMORY value: {payload:?}"
                );
                Self::Overmemory(parse_u32(payload).context(err_msg)?)
            }
            NL80211_TXQ_STATS_COLLISIONS => {
                let err_msg = format!(
                    "Invalid NL80211_TXQ_STATS_COLLISIONS value: {payload:?}"
                );
                Self::Collisions(parse_u32(payload).context(err_msg)?)
            }
            NL80211_TXQ_STATS_TX_BYTES => {
                let err_msg = format!(
                    "Invalid NL80211_TXQ_STATS_TX_BYTES value: {payload:?}"
                );
                Self::TxBytes(parse_u32(payload).context(err_msg)?)
            }
            NL80211_TXQ_STATS_TX_PACKETS => {
                let err_msg = format!(
                    "Invalid NL80211_TXQ_STATS_TX_PACKETS value: {payload:?}"
                );
                Self::TxPackets(parse_u32(payload).context(err_msg)?)
            }
            NL80211_TXQ_STATS_MAX_FLOWS => {
                let err_msg = format!(
                    "Invalid NL80211_TXQ_STATS_MAX_FLOWS value: {payload:?}"
                );
                Self::MaxFlows(parse_u32(payload).context(err_msg)?)
            }
            _ => Self::Other(
                DefaultNla::parse(buf).context("invalid NLA (unknown kind)")?,
            ),
        })
    }
}
