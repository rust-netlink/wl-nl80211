// SPDX-License-Identifier: MIT

use std::convert::TryInto;

use anyhow::Context;
use byteorder::{ByteOrder, NativeEndian};
use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer, NlasIterator},
    parsers::{parse_u16, parse_u32, parse_u64, parse_u8},
    Emitable, Parseable,
};

use std::fmt::Debug;

use crate::NestedNl80211TidStats;
#[cfg(doc)]
use crate::Nl80211Attr;

use super::Nl80211RateInfo;

const NL80211_STA_INFO_INACTIVE_TIME: u16 = 1;
const NL80211_STA_INFO_RX_BYTES: u16 = 2;
const NL80211_STA_INFO_TX_BYTES: u16 = 3;
const NL80211_STA_INFO_LLID: u16 = 4;
const NL80211_STA_INFO_PLID: u16 = 5;
const NL80211_STA_INFO_PLINK_STATE: u16 = 6;
const NL80211_STA_INFO_SIGNAL: u16 = 7;
const NL80211_STA_INFO_TX_BITRATE: u16 = 8;
const NL80211_STA_INFO_RX_PACKETS: u16 = 9;
const NL80211_STA_INFO_TX_PACKETS: u16 = 10;
const NL80211_STA_INFO_TX_RETRIES: u16 = 11;
const NL80211_STA_INFO_TX_FAILED: u16 = 12;
const NL80211_STA_INFO_SIGNAL_AVG: u16 = 13;
const NL80211_STA_INFO_RX_BITRATE: u16 = 14;
const NL80211_STA_INFO_BSS_PARAM: u16 = 15;
const NL80211_STA_INFO_CONNECTED_TIME: u16 = 16;
const NL80211_STA_INFO_STA_FLAGS: u16 = 17;
const NL80211_STA_INFO_BEACON_LOSS: u16 = 18;
const NL80211_STA_INFO_T_OFFSET: u16 = 19;
const NL80211_STA_INFO_LOCAL_PM: u16 = 20;
const NL80211_STA_INFO_PEER_PM: u16 = 21;
const NL80211_STA_INFO_NONPEER_PM: u16 = 22;
const NL80211_STA_INFO_RX_BYTES64: u16 = 23;
const NL80211_STA_INFO_TX_BYTES64: u16 = 24;
const NL80211_STA_INFO_CHAIN_SIGNAL: u16 = 25;
const NL80211_STA_INFO_CHAIN_SIGNAL_AVG: u16 = 26;
const NL80211_STA_INFO_EXPECTED_THROUGHPUT: u16 = 27;
const NL80211_STA_INFO_RX_DROP_MISC: u16 = 28;
const NL80211_STA_INFO_BEACON_RX: u16 = 29;
const NL80211_STA_INFO_BEACON_SIGNAL_AVG: u16 = 30;
const NL80211_STA_INFO_TID_STATS: u16 = 31;
const NL80211_STA_INFO_RX_DURATION: u16 = 32;
const NL80211_STA_INFO_ACK_SIGNAL: u16 = 34;
const NL80211_STA_INFO_ACK_SIGNAL_AVG: u16 = 35;
const NL80211_STA_INFO_RX_MPDUS: u16 = 36;
const NL80211_STA_INFO_FCS_ERROR_COUNT: u16 = 37;
const NL80211_STA_INFO_CONNECTED_TO_GATE: u16 = 38;
const NL80211_STA_INFO_TX_DURATION: u16 = 39;
const NL80211_STA_INFO_AIRTIME_WEIGHT: u16 = 40;
const NL80211_STA_INFO_AIRTIME_LINK_METRIC: u16 = 41;
const NL80211_STA_INFO_ASSOC_AT_BOOTTIME: u16 = 42;
const NL80211_STA_INFO_CONNECTED_TO_AS: u16 = 43;

/// Station information
///
/// These attribute types are used with [`Nl80211Attr::StationInfo`]
/// when getting information about a station.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Nl80211StationInfo {
    /// Time since last activity (msecs)
    InactiveTime(u32),
    /// Total transmitted bytes (MPDU length)
    TxBytes(u32),
    /// Total received bytes (MPDU length)
    RxBytes(u32),
    /// Total transmitted bytes (MPDU length)
    TxBytes64(u64),
    /// Total received bytes (MPDU length)
    RxBytes64(u64),
    /// Signal strength of last received PPDU (dBm)
    Signal(i8),
    /// Signal strength average (u8, dBm)
    SignalAvg(i8),
    /// Current unicast transmission rate.
    /// possible, see [`Nl80211RateInfo`]
    TxBitrate(Vec<Nl80211RateInfo>),
    ///  Last unicast data frame receive rate.
    RxBitrate(Vec<Nl80211RateInfo>),
    /// Total transmitted packets (MSDUs and MMPDUs)
    TxPackets(u32),
    /// Total received packets (MSDUs and MMPDUs)
    RxPackets(u32),
    /// Total number of received packets (MPDUs)
    RxMpdus(u32),
    /// Total retries (MPDUs)
    TxRetries(u32),
    /// Total failed packets (MPDUs) (u32, to this station)
    TxFailed(u32),
    /// Transmitted packets dropped for unspecified reasons
    RxDropMisc(u64),
    /// Total number of packets (MPDUs) received with an FCS error . This count
    /// may not include some packets with an FCS error due to TA corruption.
    /// Hence this counter might not be fully accurate.
    FcsErrorCount(u32),
    /// The station's mesh LLID
    Llid(u16),
    /// The station's mesh PLID
    Plid(u16),
    /// Peer link state for the station (see [`Nl80211PeerLinkState`])
    PeerLinkState(Nl80211PeerLinkState),
    /// Current station's view of BSS,
    BssParam(Vec<Nl80211StationBssParam>),
    /// Time since the station is last connected
    ConnectedTime(u32),
    /// Contains a [Nl80211StationFlagUpdate]
    StationFlags(Nl80211StationFlagUpdate),
    /// Timing offset with respect to this station
    TimingOffset(i64),
    /// Local mesh station link-specific power mode
    LocalPowerMode(Nl80211MeshPowerMode),
    /// Peer mesh station link-specific power mode
    PeerPowerMode(Nl80211MeshPowerMode),
    /// Neighbor mesh station power save mode towards non-peer station
    NonPeerPowerMode(Nl80211MeshPowerMode),
    /// Per-chain signal strength of last PPDU. Contains a array of
    /// signal strength attributes (dBm)
    ChainSignal(Vec<i8>),
    /// Per-chain signal strength average. Same format as
    /// [`Nl80211StationInfo::ChainSignal`]
    ChainSignalAvg(Vec<i8>),
    /// Expected throughput considering also the 802.11 header (kbps)
    ExpectedThroughput(u32),
    /// Number of beacons received from this peer
    BeaconRx(u64),
    /// Signal strength average for beacons only (dBm)
    BeaconSignalAvg(i8),
    /// Count of times beacon loss was detected
    BeaconLoss(u32),
    /// This is a nested attribute where each the inner attribute number is the
    /// TID+1 and the special TID 16 (i.e. value 17) is used for non-QoS
    /// frames; each one of those is again nested with &enum nl80211_tid_stats
    /// attributes carrying the actual values.
    TidStats(Vec<NestedNl80211TidStats>),
    /// Aggregate PPDU duration for all frames sent to the station (usec)
    TxDuration(u64),
    /// Aggregate PPDU duration for all frames received from the station (usec)
    RxDuration(u64),
    /// Signal strength of the last ACK frame (dBm)
    AckSignal(i8),
    /// Average signal strength of ACK frames (dBm)
    AckSignalAvg(i8),
    /// Set to true if the station has a path to a mesh gate
    ConnectedToGate(bool),
    /// Current airtime weight for station
    AirtimeWeight(u16),
    /// Airtime link metric for mesh station
    AirtimeLinkMetric(u16),
    /// Timestamp (nanoseconds) of station's association
    AssociationAtBoottime(u64),
    /// Set to true if the station has a path to an authentication server
    ConnectedToAuthServer(bool),

    Other(DefaultNla),
}

impl Nla for Nl80211StationInfo {
    fn value_len(&self) -> usize {
        match self {
            Self::Signal(_)
            | Self::SignalAvg(_)
            | Self::AckSignal(_)
            | Self::AckSignalAvg(_)
            | Self::BeaconSignalAvg(_) => 1,
            Self::PeerLinkState(_)
            | Self::ConnectedToGate(_)
            | Self::ConnectedToAuthServer(_) => 1,
            Self::Llid(_)
            | Self::Plid(_)
            | Self::AirtimeWeight(_)
            | Self::AirtimeLinkMetric(_) => 2,
            Self::InactiveTime(_)
            | Self::TxBytes(_)
            | Self::RxBytes(_)
            | Self::TxPackets(_)
            | Self::RxPackets(_)
            | Self::RxMpdus(_)
            | Self::TxRetries(_)
            | Self::TxFailed(_)
            | Self::FcsErrorCount(_)
            | Self::ConnectedTime(_)
            | Self::LocalPowerMode(_)
            | Self::PeerPowerMode(_)
            | Self::NonPeerPowerMode(_)
            | Self::ExpectedThroughput(_)
            | Self::BeaconLoss(_) => 4,
            Self::TxBytes64(_)
            | Self::RxBytes64(_)
            | Self::RxDropMisc(_)
            | Self::StationFlags(_)
            | Self::TimingOffset(_)
            | Self::BeaconRx(_)
            | Self::TxDuration(_)
            | Self::RxDuration(_)
            | Self::AssociationAtBoottime(_) => 8,
            Self::TxBitrate(nlas) | Self::RxBitrate(nlas) => {
                nlas.as_slice().buffer_len()
            }
            Self::BssParam(nlas) => nlas.as_slice().buffer_len(),
            Self::ChainSignal(d) | Self::ChainSignalAvg(d) => d.len(),
            Self::TidStats(nlas) => nlas.as_slice().buffer_len(),
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Nl80211StationInfo::InactiveTime(_) => {
                NL80211_STA_INFO_INACTIVE_TIME
            }
            Nl80211StationInfo::TxBytes(_) => NL80211_STA_INFO_TX_BYTES,
            Nl80211StationInfo::RxBytes(_) => NL80211_STA_INFO_RX_BYTES,
            Nl80211StationInfo::TxBytes64(_) => NL80211_STA_INFO_TX_BYTES64,
            Nl80211StationInfo::RxBytes64(_) => NL80211_STA_INFO_RX_BYTES64,
            Nl80211StationInfo::Signal(_) => NL80211_STA_INFO_SIGNAL,
            Nl80211StationInfo::SignalAvg(_) => NL80211_STA_INFO_SIGNAL_AVG,
            Nl80211StationInfo::TxBitrate(_) => NL80211_STA_INFO_TX_BITRATE,
            Nl80211StationInfo::RxBitrate(_) => NL80211_STA_INFO_RX_BITRATE,
            Nl80211StationInfo::TxPackets(_) => NL80211_STA_INFO_TX_PACKETS,
            Nl80211StationInfo::RxPackets(_) => NL80211_STA_INFO_RX_PACKETS,
            Nl80211StationInfo::RxMpdus(_) => NL80211_STA_INFO_RX_MPDUS,
            Nl80211StationInfo::TxRetries(_) => NL80211_STA_INFO_TX_RETRIES,
            Nl80211StationInfo::TxFailed(_) => NL80211_STA_INFO_TX_FAILED,
            Nl80211StationInfo::RxDropMisc(_) => NL80211_STA_INFO_RX_DROP_MISC,
            Nl80211StationInfo::FcsErrorCount(_) => {
                NL80211_STA_INFO_FCS_ERROR_COUNT
            }
            Nl80211StationInfo::Llid(_) => NL80211_STA_INFO_LLID,
            Nl80211StationInfo::Plid(_) => NL80211_STA_INFO_PLID,
            Nl80211StationInfo::PeerLinkState(_) => {
                NL80211_STA_INFO_PLINK_STATE
            }
            Nl80211StationInfo::BssParam(_) => NL80211_STA_INFO_BSS_PARAM,
            Nl80211StationInfo::ConnectedTime(_) => {
                NL80211_STA_INFO_CONNECTED_TIME
            }
            Nl80211StationInfo::StationFlags(_) => NL80211_STA_INFO_STA_FLAGS,
            Nl80211StationInfo::TimingOffset(_) => NL80211_STA_INFO_T_OFFSET,
            Nl80211StationInfo::LocalPowerMode(_) => NL80211_STA_INFO_LOCAL_PM,
            Nl80211StationInfo::PeerPowerMode(_) => NL80211_STA_INFO_PEER_PM,
            Nl80211StationInfo::NonPeerPowerMode(_) => {
                NL80211_STA_INFO_NONPEER_PM
            }
            Nl80211StationInfo::ChainSignal(_) => NL80211_STA_INFO_CHAIN_SIGNAL,
            Nl80211StationInfo::ChainSignalAvg(_) => {
                NL80211_STA_INFO_CHAIN_SIGNAL_AVG
            }
            Nl80211StationInfo::ExpectedThroughput(_) => {
                NL80211_STA_INFO_EXPECTED_THROUGHPUT
            }
            Nl80211StationInfo::BeaconRx(_) => NL80211_STA_INFO_BEACON_RX,
            Nl80211StationInfo::BeaconSignalAvg(_) => {
                NL80211_STA_INFO_BEACON_SIGNAL_AVG
            }
            Nl80211StationInfo::BeaconLoss(_) => NL80211_STA_INFO_BEACON_LOSS,
            Nl80211StationInfo::TidStats(_) => NL80211_STA_INFO_TID_STATS,
            Nl80211StationInfo::TxDuration(_) => NL80211_STA_INFO_TX_DURATION,
            Nl80211StationInfo::RxDuration(_) => NL80211_STA_INFO_RX_DURATION,
            Nl80211StationInfo::AckSignal(_) => NL80211_STA_INFO_ACK_SIGNAL,
            Nl80211StationInfo::AckSignalAvg(_) => {
                NL80211_STA_INFO_ACK_SIGNAL_AVG
            }
            Nl80211StationInfo::ConnectedToGate(_) => {
                NL80211_STA_INFO_CONNECTED_TO_GATE
            }
            Nl80211StationInfo::AirtimeWeight(_) => {
                NL80211_STA_INFO_AIRTIME_WEIGHT
            }
            Nl80211StationInfo::AirtimeLinkMetric(_) => {
                NL80211_STA_INFO_AIRTIME_LINK_METRIC
            }
            Nl80211StationInfo::AssociationAtBoottime(_) => {
                NL80211_STA_INFO_ASSOC_AT_BOOTTIME
            }
            Nl80211StationInfo::ConnectedToAuthServer(_) => {
                NL80211_STA_INFO_CONNECTED_TO_AS
            }
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Nl80211StationInfo::Signal(d)
            | Nl80211StationInfo::SignalAvg(d)
            | Nl80211StationInfo::BeaconSignalAvg(d)
            | Nl80211StationInfo::AckSignal(d)
            | Nl80211StationInfo::AckSignalAvg(d) => buffer[0] = *d as u8,
            Nl80211StationInfo::Llid(d)
            | Nl80211StationInfo::Plid(d)
            | Nl80211StationInfo::AirtimeWeight(d)
            | Nl80211StationInfo::AirtimeLinkMetric(d) => {
                NativeEndian::write_u16(buffer, *d)
            }
            Nl80211StationInfo::InactiveTime(d)
            | Nl80211StationInfo::TxBytes(d)
            | Nl80211StationInfo::RxBytes(d)
            | Nl80211StationInfo::TxPackets(d)
            | Nl80211StationInfo::RxPackets(d)
            | Nl80211StationInfo::RxMpdus(d)
            | Nl80211StationInfo::TxRetries(d)
            | Nl80211StationInfo::TxFailed(d)
            | Nl80211StationInfo::FcsErrorCount(d)
            | Nl80211StationInfo::ConnectedTime(d)
            | Nl80211StationInfo::ExpectedThroughput(d)
            | Nl80211StationInfo::BeaconLoss(d) => {
                NativeEndian::write_u32(buffer, *d)
            }
            Nl80211StationInfo::TxBytes64(d)
            | Nl80211StationInfo::RxBytes64(d)
            | Nl80211StationInfo::RxDropMisc(d)
            | Nl80211StationInfo::BeaconRx(d)
            | Nl80211StationInfo::TxDuration(d)
            | Nl80211StationInfo::RxDuration(d)
            | Nl80211StationInfo::AssociationAtBoottime(d) => {
                NativeEndian::write_u64(buffer, *d)
            }
            Nl80211StationInfo::TimingOffset(d) => {
                NativeEndian::write_i64(buffer, *d)
            }
            Nl80211StationInfo::TxBitrate(nlas)
            | Nl80211StationInfo::RxBitrate(nlas) => {
                nlas.as_slice().emit(buffer)
            }
            Nl80211StationInfo::PeerLinkState(d) => buffer[0] = (*d).into(),
            Nl80211StationInfo::BssParam(nlas) => nlas.as_slice().emit(buffer),
            Nl80211StationInfo::StationFlags(d) => {
                NativeEndian::write_u32(&mut buffer[0..4], (&d.mask).into());
                NativeEndian::write_u32(&mut buffer[4..8], (&d.set).into());
            }
            Nl80211StationInfo::LocalPowerMode(d)
            | Nl80211StationInfo::PeerPowerMode(d)
            | Nl80211StationInfo::NonPeerPowerMode(d) => {
                NativeEndian::write_u32(buffer, (*d).into())
            }
            Nl80211StationInfo::ChainSignal(d)
            | Nl80211StationInfo::ChainSignalAvg(d) => {
                let data: Vec<u8> =
                    d.as_slice().iter().map(|d| *d as u8).collect();
                buffer.copy_from_slice(data.as_slice());
            }
            Nl80211StationInfo::TidStats(nlas) => nlas.as_slice().emit(buffer),
            Nl80211StationInfo::ConnectedToGate(d)
            | Nl80211StationInfo::ConnectedToAuthServer(d) => {
                buffer[0] = (*d).into()
            }
            Self::Other(attr) => attr.emit(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for Nl80211StationInfo
{
    fn parse(
        buf: &NlaBuffer<&'a T>,
    ) -> Result<Self, netlink_packet_utils::DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NL80211_STA_INFO_INACTIVE_TIME => {
                let err_msg = format!(
                    "Invalid NL80211_STA_INFO_INACTIVE_TIME value {payload:?}"
                );
                Self::InactiveTime(parse_u32(payload).context(err_msg)?)
            }
            NL80211_STA_INFO_RX_BYTES => {
                let err_msg = format!(
                    "Invalid NL80211_STA_INFO_RX_BYTES value {payload:?}"
                );
                Self::RxBytes(parse_u32(payload).context(err_msg)?)
            }
            NL80211_STA_INFO_TX_BYTES => {
                let err_msg = format!(
                    "Invalid NL80211_STA_INFO_TX_BYTES value {payload:?}"
                );
                Self::TxBytes(parse_u32(payload).context(err_msg)?)
            }
            NL80211_STA_INFO_LLID => {
                let err_msg =
                    format!("Invalid NL80211_STA_INFO_LLID value {payload:?}");
                Self::Llid(parse_u16(payload).context(err_msg)?)
            }
            NL80211_STA_INFO_PLID => {
                let err_msg =
                    format!("Invalid NL80211_STA_INFO_PLID value {payload:?}");
                Self::Plid(parse_u16(payload).context(err_msg)?)
            }
            NL80211_STA_INFO_PLINK_STATE => {
                let err_msg = format!(
                    "Invalid NL80211_STA_INFO_PLINK_STATE value {payload:?}"
                );
                Self::PeerLinkState(parse_u8(payload).context(err_msg)?.into())
            }
            NL80211_STA_INFO_SIGNAL => {
                let err_msg = format!(
                    "Invalid NL80211_STA_INFO_SIGNAL value {payload:?}"
                );
                Self::Signal(parse_u8(payload).context(err_msg)? as i8)
            }
            NL80211_STA_INFO_TX_BITRATE => {
                let err_msg = format!(
                    "Invalid NL80211_STA_INFO_TX_BITRATE value {payload:?}"
                );
                let mut nlas = Vec::new();
                for nla in NlasIterator::new(payload) {
                    let nla = &nla.context(err_msg.clone())?;
                    nlas.push(
                        Nl80211RateInfo::parse(nla).context(err_msg.clone())?,
                    );
                }
                Self::TxBitrate(nlas)
            }
            NL80211_STA_INFO_RX_PACKETS => {
                let err_msg = format!(
                    "Invalid NL80211_STA_INFO_RX_PACKETS value {payload:?}"
                );
                Self::RxPackets(parse_u32(payload).context(err_msg)?)
            }
            NL80211_STA_INFO_TX_PACKETS => {
                let err_msg = format!(
                    "Invalid NL80211_STA_INFO_TX_PACKETS value {payload:?}"
                );
                Self::TxPackets(parse_u32(payload).context(err_msg)?)
            }
            NL80211_STA_INFO_TX_RETRIES => {
                let err_msg = format!(
                    "Invalid NL80211_STA_INFO_TX_RETRIES value {payload:?}"
                );
                Self::TxRetries(parse_u32(payload).context(err_msg)?)
            }
            NL80211_STA_INFO_TX_FAILED => {
                let err_msg = format!(
                    "Invalid NL80211_STA_INFO_TX_FAILED value {payload:?}"
                );
                Self::TxFailed(parse_u32(payload).context(err_msg)?)
            }
            NL80211_STA_INFO_SIGNAL_AVG => {
                let err_msg = format!(
                    "Invalid NL80211_STA_INFO_SIGNAL_AVG value {payload:?}"
                );
                Self::SignalAvg(parse_u8(payload).context(err_msg)? as i8)
            }
            NL80211_STA_INFO_RX_BITRATE => {
                let err_msg = format!(
                    "Invalid NL80211_STA_INFO_RX_BITRATE value {payload:?}"
                );
                let mut nlas = Vec::new();
                for nla in NlasIterator::new(payload) {
                    let nla = &nla.context(err_msg.clone())?;
                    nlas.push(
                        Nl80211RateInfo::parse(nla).context(err_msg.clone())?,
                    );
                }
                Self::RxBitrate(nlas)
            }
            NL80211_STA_INFO_BSS_PARAM => {
                let err_msg = format!(
                    "Invalid NL80211_STA_INFO_BSS_PARAM value {payload:?}"
                );
                let mut nlas = Vec::new();
                for nla in NlasIterator::new(payload) {
                    let nla = &nla.context(err_msg.clone())?;
                    nlas.push(
                        Nl80211StationBssParam::parse(nla)
                            .context(err_msg.clone())?,
                    );
                }
                Self::BssParam(nlas)
            }
            NL80211_STA_INFO_CONNECTED_TIME => {
                let err_msg = format!(
                    "Invalid NL80211_STA_INFO_CONNECTED_TIME value {payload:?}"
                );
                Self::ConnectedTime(parse_u32(payload).context(err_msg)?)
            }
            NL80211_STA_INFO_STA_FLAGS => {
                Self::StationFlags(if payload.len() == 8 {
                    let err_msg = format!(
                        "Invalid NL80211_STA_INFO_STA_FLAGS value {payload:?}"
                    );
                    let mask =
                        parse_u32(&payload[0..4]).context(err_msg.clone())?;
                    let set = parse_u32(&payload[4..8]).context(err_msg)?;
                    Nl80211StationFlagUpdate {
                        mask: mask.into(),
                        set: set.into(),
                    }
                } else {
                    return Err(format!(
                    "Invalid length of NL80211_STA_INFO_STA_FLAGS, expected length {} got {:?}",
                    8, payload
                )
                .into());
                })
            }
            NL80211_STA_INFO_BEACON_LOSS => {
                let err_msg = format!(
                    "Invalid NL80211_STA_INFO_BEACON_LOSS value {payload:?}"
                );
                Self::BeaconLoss(parse_u32(payload).context(err_msg)?)
            }
            NL80211_STA_INFO_T_OFFSET => {
                let err_msg = format!(
                    "Invalid NL80211_STA_INFO_T_OFFSET value {payload:?}"
                );
                Self::TimingOffset(i64::from_ne_bytes(
                    payload.try_into().context(err_msg)?,
                ))
            }
            NL80211_STA_INFO_LOCAL_PM => {
                let err_msg = format!(
                    "Invalid NL80211_STA_INFO_LOCAL_PM value {payload:?}"
                );
                Self::LocalPowerMode(
                    parse_u32(payload).context(err_msg)?.into(),
                )
            }
            NL80211_STA_INFO_PEER_PM => {
                let err_msg = format!(
                    "Invalid NL80211_STA_INFO_PEER_PM value {payload:?}"
                );
                Self::PeerPowerMode(parse_u32(payload).context(err_msg)?.into())
            }
            NL80211_STA_INFO_NONPEER_PM => {
                let err_msg = format!(
                    "Invalid NL80211_STA_INFO_NONPEER_PM value {payload:?}"
                );
                Self::NonPeerPowerMode(
                    parse_u32(payload).context(err_msg)?.into(),
                )
            }
            NL80211_STA_INFO_RX_BYTES64 => {
                let err_msg = format!(
                    "Invalid NL80211_STA_INFO_RX_BYTES64 value {payload:?}"
                );
                Self::RxBytes64(parse_u64(payload).context(err_msg)?)
            }
            NL80211_STA_INFO_TX_BYTES64 => {
                let err_msg = format!(
                    "Invalid NL80211_STA_INFO_TX_BYTES64 value {payload:?}"
                );
                Self::TxBytes64(parse_u64(payload).context(err_msg)?)
            }
            NL80211_STA_INFO_CHAIN_SIGNAL => {
                Self::ChainSignal(payload.iter().map(|d| *d as i8).collect())
            }
            NL80211_STA_INFO_CHAIN_SIGNAL_AVG => {
                Self::ChainSignalAvg(payload.iter().map(|d| *d as i8).collect())
            }
            NL80211_STA_INFO_EXPECTED_THROUGHPUT => {
                let err_msg = format!(
                    "Invalid NL80211_STA_INFO_EXPECTED_THROUGHPUT value {payload:?}"
                );
                Self::ExpectedThroughput(parse_u32(payload).context(err_msg)?)
            }
            NL80211_STA_INFO_RX_DROP_MISC => {
                let err_msg = format!(
                    "Invalid NL80211_STA_INFO_RX_DROP_MISC value {payload:?}"
                );
                Self::RxDropMisc(parse_u64(payload).context(err_msg)?)
            }
            NL80211_STA_INFO_BEACON_RX => {
                let err_msg = format!(
                    "Invalid NL80211_STA_INFO_BEACON_RX value {payload:?}"
                );
                Self::BeaconRx(parse_u64(payload).context(err_msg)?)
            }
            NL80211_STA_INFO_BEACON_SIGNAL_AVG => {
                let err_msg = format!(
                    "Invalid NL80211_STA_INFO_BEACON_SIGNAL_AVG value {payload:?}"
                );
                Self::BeaconSignalAvg(parse_u8(payload).context(err_msg)? as i8)
            }
            NL80211_STA_INFO_TID_STATS => {
                let err_msg = format!(
                    "Invalid NL80211_STA_INFO_TID_STATS value {payload:?}"
                );
                let mut nlas = Vec::new();
                let _t = NlasIterator::new(payload);
                for nla in NlasIterator::new(payload) {
                    let nla = &nla.context(err_msg.clone())?;
                    nlas.push(
                        NestedNl80211TidStats::parse(nla)
                            .context(err_msg.clone())?,
                    );
                }
                Self::TidStats(nlas)
            }
            NL80211_STA_INFO_RX_DURATION => {
                let err_msg = format!(
                    "Invalid NL80211_STA_INFO_RX_DURATION value {payload:?}"
                );
                Self::RxDuration(parse_u64(payload).context(err_msg)?)
            }
            NL80211_STA_INFO_ACK_SIGNAL => {
                let err_msg = format!(
                    "Invalid NL80211_STA_INFO_ACK_SIGNAL value {payload:?}"
                );
                Self::AckSignal(parse_u8(payload).context(err_msg)? as i8)
            }
            NL80211_STA_INFO_ACK_SIGNAL_AVG => {
                let err_msg = format!(
                    "Invalid NL80211_STA_INFO_ACK_SIGNAL_AVG value {payload:?}"
                );
                Self::AckSignalAvg(*payload.first().context(err_msg)? as i8)
            }
            NL80211_STA_INFO_RX_MPDUS => {
                let err_msg = format!(
                    "Invalid NL80211_STA_INFO_RX_MPDUS value {payload:?}"
                );
                Self::RxMpdus(parse_u32(payload).context(err_msg)?)
            }
            NL80211_STA_INFO_FCS_ERROR_COUNT => {
                let err_msg = format!(
                    "Invalid NL80211_STA_INFO_FCS_ERROR_COUNT value {payload:?}"
                );
                Self::FcsErrorCount(parse_u32(payload).context(err_msg)?)
            }
            NL80211_STA_INFO_CONNECTED_TO_GATE => {
                let err_msg = format!(
                    "Invalid NL80211_STA_INFO_CONNECTED_TO_GATE value {payload:?}"
                );
                Self::ConnectedToGate(parse_u8(payload).context(err_msg)? == 1)
            }
            NL80211_STA_INFO_TX_DURATION => {
                let err_msg = format!(
                    "Invalid NL80211_STA_INFO_TX_DURATION value {payload:?}"
                );
                Self::TxDuration(parse_u64(payload).context(err_msg)?)
            }
            NL80211_STA_INFO_AIRTIME_WEIGHT => {
                let err_msg = format!(
                    "Invalid NL80211_STA_INFO_AIRTIME_WEIGHT value {payload:?}"
                );
                Self::AirtimeWeight(parse_u16(payload).context(err_msg)?)
            }
            NL80211_STA_INFO_AIRTIME_LINK_METRIC => {
                let err_msg = format!(
                    "Invalid NL80211_STA_INFO_AIRTIME_LINK_METRIC value {payload:?}"
                );
                Self::AirtimeLinkMetric(parse_u16(payload).context(err_msg)?)
            }
            NL80211_STA_INFO_ASSOC_AT_BOOTTIME => {
                let err_msg = format!(
                    "Invalid NL80211_STA_INFO_ASSOC_AT_BOOTTIME value {payload:?}"
                );
                Self::AssociationAtBoottime(
                    parse_u64(payload).context(err_msg)?,
                )
            }
            NL80211_STA_INFO_CONNECTED_TO_AS => {
                let err_msg = format!(
                    "Invalid NL80211_STA_INFO_CONNECTED_TO_AS value {payload:?}"
                );
                Self::ConnectedToAuthServer(
                    parse_u8(payload).context(err_msg)? == 1,
                )
            }
            _ => Self::Other(
                DefaultNla::parse(buf).context("invalid NLA (unknown kind)")?,
            ),
        })
    }
}

pub const NL80211_PLINK_LISTEN: u8 = 0;
pub const NL80211_PLINK_OPN_SNT: u8 = 1;
pub const NL80211_PLINK_OPN_RCVD: u8 = 2;
pub const NL80211_PLINK_CNF_RCVD: u8 = 3;
pub const NL80211_PLINK_ESTAB: u8 = 4;
pub const NL80211_PLINK_HOLDING: u8 = 5;
pub const NL80211_PLINK_BLOCKED: u8 = 6;

/// State of a mesh peer link finite state machine
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Nl80211PeerLinkState {
    /// Initial state, considered the implicit state of non existent mesh peer
    /// links
    Listen,
    /// Mesh peer link open frame has been sent to this mesh peer
    OpenSent,
    /// Mesh plink open frame has been received from this mesh peer
    OpenReceived,
    /// Mesh plink confirm frame has been received from this mesh peer
    ConfirmReceived,
    /// Mesh peer link is established
    Established,
    /// Mesh peer link is being closed or cancelled
    Holding,
    /// All frames transmitted from this mesh plink are discarded, except for
    /// authentication frames
    Blocked,
    Other(u8),
}

impl From<u8> for Nl80211PeerLinkState {
    fn from(d: u8) -> Self {
        match d {
            NL80211_PLINK_LISTEN => Self::Listen,
            NL80211_PLINK_OPN_SNT => Self::OpenSent,
            NL80211_PLINK_OPN_RCVD => Self::OpenReceived,
            NL80211_PLINK_CNF_RCVD => Self::ConfirmReceived,
            NL80211_PLINK_ESTAB => Self::Established,
            NL80211_PLINK_HOLDING => Self::Holding,
            NL80211_PLINK_BLOCKED => Self::Blocked,
            _ => Self::Other(d),
        }
    }
}

impl From<Nl80211PeerLinkState> for u8 {
    fn from(v: Nl80211PeerLinkState) -> u8 {
        match v {
            Nl80211PeerLinkState::Listen => NL80211_PLINK_LISTEN,
            Nl80211PeerLinkState::OpenSent => NL80211_PLINK_OPN_SNT,
            Nl80211PeerLinkState::OpenReceived => NL80211_PLINK_OPN_RCVD,
            Nl80211PeerLinkState::ConfirmReceived => NL80211_PLINK_CNF_RCVD,
            Nl80211PeerLinkState::Established => NL80211_PLINK_ESTAB,
            Nl80211PeerLinkState::Holding => NL80211_PLINK_HOLDING,
            Nl80211PeerLinkState::Blocked => NL80211_PLINK_BLOCKED,
            Nl80211PeerLinkState::Other(d) => d,
        }
    }
}

const NL80211_STA_BSS_PARAM_CTS_PROT: u16 = 1;
const NL80211_STA_BSS_PARAM_SHORT_PREAMBLE: u16 = 2;
const NL80211_STA_BSS_PARAM_SHORT_SLOT_TIME: u16 = 3;
const NL80211_STA_BSS_PARAM_DTIM_PERIOD: u16 = 4;
const NL80211_STA_BSS_PARAM_BEACON_INTERVAL: u16 = 5;

/// BSS information collected by station
///
/// These attribute types are used with [`Nl80211StationInfo::BssParam`]
/// when getting information about the bitrate of a station.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Nl80211StationBssParam {
    CtsProtection,
    ShortPreamble,
    ShortSlotTime,
    /// DTIM period for beaconing
    DtimPeriod(u8),
    BeaconInterval(u16),

    Other(DefaultNla),
}

impl Nla for Nl80211StationBssParam {
    fn value_len(&self) -> usize {
        match self {
            Self::CtsProtection | Self::ShortPreamble | Self::ShortSlotTime => {
                0
            }
            Self::DtimPeriod(_) => 1,
            Self::BeaconInterval(_) | Self::Other(_) => 2,
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::CtsProtection => NL80211_STA_BSS_PARAM_CTS_PROT,
            Self::ShortPreamble => NL80211_STA_BSS_PARAM_SHORT_PREAMBLE,
            Self::ShortSlotTime => NL80211_STA_BSS_PARAM_SHORT_SLOT_TIME,
            Self::DtimPeriod(_) => NL80211_STA_BSS_PARAM_DTIM_PERIOD,
            Self::BeaconInterval(_) => NL80211_STA_BSS_PARAM_BEACON_INTERVAL,
            Self::Other(d) => d.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::CtsProtection | Self::ShortPreamble | Self::ShortSlotTime => {
            }
            Self::DtimPeriod(d) => buffer[0] = *d,
            Self::BeaconInterval(d) => NativeEndian::write_u16(buffer, *d),
            Self::Other(d) => (*d).emit(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for Nl80211StationBssParam
{
    fn parse(
        buf: &NlaBuffer<&'a T>,
    ) -> Result<Self, netlink_packet_utils::DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NL80211_STA_BSS_PARAM_CTS_PROT => Self::CtsProtection,
            NL80211_STA_BSS_PARAM_SHORT_PREAMBLE => Self::ShortPreamble,
            NL80211_STA_BSS_PARAM_SHORT_SLOT_TIME => Self::ShortSlotTime,
            NL80211_STA_BSS_PARAM_DTIM_PERIOD => {
                let err_msg = format!(
                    "Invalid NL80211_STA_BSS_PARAM_DTIM_PERIOD value {payload:?}"
                );
                Self::DtimPeriod(parse_u8(payload).context(err_msg)?)
            }
            NL80211_STA_BSS_PARAM_BEACON_INTERVAL => {
                let err_msg = format!(
                    "Invalid NL80211_STA_BSS_PARAM_BEACON_INTERVAL value {payload:?}"
                );
                Self::BeaconInterval(parse_u16(payload).context(err_msg)?)
            }
            _ => Self::Other(
                DefaultNla::parse(buf).context("invalid NLA (unknown kind)")?,
            ),
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Nl80211StationFlagUpdate {
    /// Mask of station flags to set
    mask: VecNl80211StationFlag,
    /// Which values to set them to
    set: VecNl80211StationFlag,
}

pub const NL80211_STA_FLAG_AUTHORIZED: u32 = 1;
pub const NL80211_STA_FLAG_SHORT_PREAMBLE: u32 = 2;
pub const NL80211_STA_FLAG_WME: u32 = 3;
pub const NL80211_STA_FLAG_MFP: u32 = 4;
pub const NL80211_STA_FLAG_AUTHENTICATED: u32 = 5;
pub const NL80211_STA_FLAG_TDLS_PEER: u32 = 6;
pub const NL80211_STA_FLAG_ASSOCIATED: u32 = 7;

/// Station flags
///
/// When a station is added to an AP interface, it is assumed to
/// be already associated (and hence authenticated.)
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub(crate) struct VecNl80211StationFlag(pub Vec<Nl80211StationFlag>);

#[non_exhaustive]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Nl80211StationFlag {
    /// Station is authorized (802.1X)
    Authorized,
    /// Station is capable of receiving frames with short barker preamble
    ShortPreamble,
    /// Station is WME/QoS capable
    Wme,
    /// Station uses management frame protection
    Mfp,
    /// Station is authenticated
    Authenticated,
    /// Station is a TDLS peer. This flag should only be used in managed mode
    /// (even in the flags mask). Note that the flag can't be changed, it is
    /// only valid while adding a station, and attempts to change it will
    /// silently be ignored (rather than rejected as errors.)
    TdlsPeer,
    /// station is associated; used with drivers that support
    /// [crate::Nl80211Features::FullApClientState] to transition a previously
    /// added station into associated state
    Associated,
    // Reserved: 25 bits,
    Other(u32),
}

impl From<u32> for Nl80211StationFlag {
    fn from(d: u32) -> Self {
        match d {
            NL80211_STA_FLAG_AUTHORIZED => Self::Authorized,
            NL80211_STA_FLAG_SHORT_PREAMBLE => Self::ShortPreamble,
            NL80211_STA_FLAG_WME => Self::Wme,
            NL80211_STA_FLAG_MFP => Self::Mfp,
            NL80211_STA_FLAG_AUTHENTICATED => Self::Authenticated,
            NL80211_STA_FLAG_TDLS_PEER => Self::TdlsPeer,
            NL80211_STA_FLAG_ASSOCIATED => Self::Associated,
            _ => Self::Other(d),
        }
    }
}

impl From<Nl80211StationFlag> for u32 {
    fn from(v: Nl80211StationFlag) -> Self {
        match v {
            Nl80211StationFlag::Authorized => NL80211_STA_FLAG_AUTHORIZED,
            Nl80211StationFlag::ShortPreamble => {
                NL80211_STA_FLAG_SHORT_PREAMBLE
            }
            Nl80211StationFlag::Wme => NL80211_STA_FLAG_WME,
            Nl80211StationFlag::Mfp => NL80211_STA_FLAG_MFP,
            Nl80211StationFlag::Authenticated => NL80211_STA_FLAG_AUTHENTICATED,
            Nl80211StationFlag::TdlsPeer => NL80211_STA_FLAG_TDLS_PEER,
            Nl80211StationFlag::Associated => NL80211_STA_FLAG_ASSOCIATED,
            Nl80211StationFlag::Other(d) => d,
        }
    }
}

impl std::fmt::Display for Nl80211StationFlag {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Nl80211StationFlag::Authorized => write!(f, "AUTHORIZED"),
            Nl80211StationFlag::ShortPreamble => write!(f, "SHORT_PREAMBLE"),
            Nl80211StationFlag::Wme => write!(f, "WME"),
            Nl80211StationFlag::Mfp => write!(f, "MFP"),
            Nl80211StationFlag::Authenticated => write!(f, "AUTHENTICATED"),
            Nl80211StationFlag::TdlsPeer => write!(f, "TDLS_PEER"),
            Nl80211StationFlag::Associated => write!(f, "ASSOCIATED"),
            Nl80211StationFlag::Other(d) => write!(f, "Other({d})"),
        }
    }
}

const ALL_STATION_FLAGS: [Nl80211StationFlag; 7] = [
    Nl80211StationFlag::Associated,
    Nl80211StationFlag::Authenticated,
    Nl80211StationFlag::Authorized,
    Nl80211StationFlag::Mfp,
    Nl80211StationFlag::ShortPreamble,
    Nl80211StationFlag::TdlsPeer,
    Nl80211StationFlag::Wme,
];

impl From<u32> for VecNl80211StationFlag {
    fn from(d: u32) -> Self {
        let mut got: u32 = 0;
        let mut ret = Vec::new();

        for flag in ALL_STATION_FLAGS {
            if (d & u32::from(flag)) > 0 {
                ret.push(flag);
                got += u32::from(flag);
            }
        }
        if got != d {
            ret.push(Nl80211StationFlag::Other(d - got));
        }

        Self(ret)
    }
}

impl From<&VecNl80211StationFlag> for u32 {
    fn from(v: &VecNl80211StationFlag) -> u32 {
        let mut d: u32 = 0;
        for flag in &v.0 {
            d += u32::from(*flag);
        }
        d
    }
}

pub const NL80211_MESH_POWER_UNKNOWN: u32 = 0;
pub const NL80211_MESH_POWER_ACTIVE: u32 = 1;
pub const NL80211_MESH_POWER_LIGHT_SLEEP: u32 = 2;
pub const NL80211_MESH_POWER_DEEP_SLEEP: u32 = 3;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Nl80211MeshPowerMode {
    Unknown,
    Active,
    LightSleep,
    DeepSleep,

    Other(u32),
}

impl From<u32> for Nl80211MeshPowerMode {
    fn from(d: u32) -> Self {
        match d {
            NL80211_MESH_POWER_UNKNOWN => Self::Unknown,
            NL80211_MESH_POWER_ACTIVE => Self::Active,
            NL80211_MESH_POWER_LIGHT_SLEEP => Self::LightSleep,
            NL80211_MESH_POWER_DEEP_SLEEP => Self::DeepSleep,
            _ => Self::Other(d),
        }
    }
}

impl From<Nl80211MeshPowerMode> for u32 {
    fn from(v: Nl80211MeshPowerMode) -> u32 {
        match v {
            Nl80211MeshPowerMode::Unknown => NL80211_MESH_POWER_UNKNOWN,
            Nl80211MeshPowerMode::Active => NL80211_MESH_POWER_ACTIVE,
            Nl80211MeshPowerMode::LightSleep => NL80211_MESH_POWER_LIGHT_SLEEP,
            Nl80211MeshPowerMode::DeepSleep => NL80211_MESH_POWER_DEEP_SLEEP,
            Nl80211MeshPowerMode::Other(d) => d,
        }
    }
}
