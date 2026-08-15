// SPDX-License-Identifier: MIT

use std::ops::Deref;

use futures::TryStream;
use netlink_packet_core::{
    parse_i32, parse_string, parse_u32, DecodeError, DefaultNla, Emitable,
    ErrorContext, Nla, NlaBuffer, NlasIterator, Parseable, NLA_F_NESTED,
    NLM_F_ACK, NLM_F_REQUEST,
};
use netlink_packet_generic::GenlMessage;

use crate::mac::ETH_ALEN;
use crate::{
    bytes::{write_i32, write_u32},
    nl80211_execute, Nl80211Attr, Nl80211Command, Nl80211Error, Nl80211Handle,
    Nl80211Message,
};

#[derive(Debug, Clone)]
pub struct Nl80211ScanScheduleRequest {
    handle: Nl80211Handle,
    attributes: Vec<Nl80211Attr>,
}

impl Nl80211ScanScheduleRequest {
    pub(crate) fn new(
        handle: Nl80211Handle,
        attributes: Vec<Nl80211Attr>,
    ) -> Self {
        Self { handle, attributes }
    }

    pub async fn execute(
        self,
    ) -> impl TryStream<Ok = GenlMessage<Nl80211Message>, Error = Nl80211Error>
    {
        let Self {
            mut handle,
            attributes,
        } = self;

        let nl80211_msg = Nl80211Message {
            cmd: Nl80211Command::StartSchedScan,
            attributes,
        };
        let flags = NLM_F_REQUEST | NLM_F_ACK;

        nl80211_execute(&mut handle, nl80211_msg, flags).await
    }
}

#[derive(Debug, Clone)]
pub struct Nl80211ScanScheduleStopRequest {
    handle: Nl80211Handle,
    attributes: Vec<Nl80211Attr>,
}

impl Nl80211ScanScheduleStopRequest {
    pub(crate) fn new(
        handle: Nl80211Handle,
        attributes: Vec<Nl80211Attr>,
    ) -> Self {
        Self { handle, attributes }
    }

    pub async fn execute(
        self,
    ) -> impl TryStream<Ok = GenlMessage<Nl80211Message>, Error = Nl80211Error>
    {
        let Self {
            mut handle,
            attributes,
        } = self;

        let nl80211_msg = Nl80211Message {
            cmd: Nl80211Command::StopSchedScan,
            attributes,
        };
        let flags = NLM_F_REQUEST | NLM_F_ACK;

        nl80211_execute(&mut handle, nl80211_msg, flags).await
    }
}

const NL80211_SCHED_SCAN_MATCH_ATTR_SSID: u16 = 1;
const NL80211_SCHED_SCAN_MATCH_ATTR_RSSI: u16 = 2;
// Linux kernel 6.11 has no code parsing these two values, only documented
//  const NL80211_SCHED_SCAN_MATCH_ATTR_RELATIVE_RSSI: u16 = 3;
//  const NL80211_SCHED_SCAN_MATCH_ATTR_RSSI_ADJUST: u16 = 4;
const NL80211_SCHED_SCAN_MATCH_ATTR_BSSID: u16 = 5;
// Linux kernel has this one marked as obsolete
// const NL80211_SCHED_SCAN_MATCH_PER_BAND_RSSI: u16 = 6;

// The kernel parses `NL80211_ATTR_SCHED_SCAN_MATCH` as a list of match sets,
// each match set being a nested attribute holding a group of match
// attributes (`Nl80211SchedScanMatchAttr`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Nl80211SchedScanMatch(pub Vec<Nl80211SchedScanMatchAttr>);

impl Deref for Nl80211SchedScanMatch {
    type Target = Vec<Nl80211SchedScanMatchAttr>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// A two-layer nested NLA: a list of attributes wrapped in a nested attribute
// whose type is the element index. The kernel parses every child of
// `NL80211_ATTR_SCHED_SCAN_MATCH`/`NL80211_ATTR_SCHED_SCAN_PLANS` as such a
// nested attribute (match set / scan plan) and ignores the type of it;
// both wpa_supplicant and iw emit them with type `index + 1`.
pub(crate) struct NestedIndexedNla<T> {
    index: u16,
    attrs: Vec<T>,
}

impl<T: Nla> Nla for NestedIndexedNla<T> {
    fn value_len(&self) -> usize {
        self.attrs.as_slice().buffer_len()
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        self.attrs.as_slice().emit(buffer);
    }

    fn kind(&self) -> u16 {
        NLA_F_NESTED | self.index
    }
}

pub(crate) struct NestedIndexedNlaList<T>(Vec<NestedIndexedNla<T>>);

impl<T> Deref for NestedIndexedNlaList<T> {
    type Target = Vec<NestedIndexedNla<T>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: Nla + Clone, S: Deref<Target = Vec<T>>> From<&Vec<S>>
    for NestedIndexedNlaList<T>
{
    fn from(attrs: &Vec<S>) -> Self {
        let mut nlas = Vec::new();
        for (i, attr) in attrs.iter().enumerate() {
            nlas.push(NestedIndexedNla {
                index: i as u16 + 1,
                attrs: attr.deref().clone(),
            });
        }
        NestedIndexedNlaList(nlas)
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for Nl80211SchedScanMatch
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let err = "Invalid NLA for NL80211_SCHED_SCAN_MATCH";
        let mut attrs = Vec::new();
        for nla in NlasIterator::new(buf.value()) {
            let nla = &nla.context(err)?;
            attrs.push(Nl80211SchedScanMatchAttr::parse(nla).context(err)?);
        }
        Ok(Self(attrs))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Nl80211SchedScanMatchAttr {
    /// SSID to be used for matching. Cannot use with
    /// [Nl80211SchedScanMatchAttr::Bssid].
    Ssid(String),
    /// RSSI threshold (in dBm) for reporting a BSS in scan results. Filtering
    /// is turned off if not specified. Note that if this attribute is in a
    /// match set of its own, then it is treated as the default value for all
    /// matchsets with an SSID, rather than being a matchset of its own without
    /// an RSSI filter. This is due to problems with how this API was
    /// implemented in the past. Also, due to the same problem, the only way to
    /// create a matchset with only an RSSI filter (with this attribute) is if
    /// there's only a single matchset with the RSSI attribute.
    Rssi(i32),
    /// BSSID to be used for matching. Cannot use with
    /// [Nl80211SchedScanMatchAttr::Ssid].
    Bssid([u8; ETH_ALEN]),
    Other(DefaultNla),
}

impl Nla for Nl80211SchedScanMatchAttr {
    fn value_len(&self) -> usize {
        match self {
            Self::Ssid(v) => v.len(),
            Self::Bssid(_) => ETH_ALEN,
            Self::Rssi(_) => 4,
            Self::Other(v) => v.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Ssid(v) => buffer.copy_from_slice(v.as_bytes()),
            Self::Bssid(v) => buffer.copy_from_slice(v),
            Self::Rssi(d) => write_i32(buffer, *d),
            Self::Other(attr) => attr.emit(buffer),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Ssid(_) => NL80211_SCHED_SCAN_MATCH_ATTR_SSID,
            Self::Bssid(_) => NL80211_SCHED_SCAN_MATCH_ATTR_BSSID,
            Self::Rssi(_) => NL80211_SCHED_SCAN_MATCH_ATTR_RSSI,
            Self::Other(attr) => attr.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for Nl80211SchedScanMatchAttr
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NL80211_SCHED_SCAN_MATCH_ATTR_SSID => {
                let err_msg = format!(
                    "Invalid NL80211_SCHED_SCAN_MATCH_ATTR_SSID value {payload:?}"
                );
                Self::Ssid(parse_string(payload).context(err_msg)?)
            }
            NL80211_SCHED_SCAN_MATCH_ATTR_RSSI => {
                let err_msg = format!(
                    "Invalid NL80211_SCHED_SCAN_MATCH_ATTR_RSSI value {payload:?}"
                );
                Self::Rssi(parse_i32(payload).context(err_msg)?)
            }
            NL80211_SCHED_SCAN_MATCH_ATTR_BSSID => {
                if payload.len() < ETH_ALEN {
                    return Err(format!(
                        "Invalid NL80211_SCHED_SCAN_MATCH_ATTR_BSSID \
                        {payload:?}"
                    )
                    .into());
                }
                let mut bssid = [0u8; ETH_ALEN];
                bssid.copy_from_slice(&payload[..ETH_ALEN]);
                Self::Bssid(bssid)
            }
            _ => Self::Other(
                DefaultNla::parse(buf).context("invalid NLA (unknown kind)")?,
            ),
        })
    }
}

const NL80211_SCHED_SCAN_PLAN_INTERVAL: u16 = 1;
const NL80211_SCHED_SCAN_PLAN_ITERATIONS: u16 = 2;

// The kernel parses `NL80211_ATTR_SCHED_SCAN_PLANS` as a list of scan plans,
// each scan plan being a nested attribute holding a group of plan attributes
// (`Nl80211SchedScanPlanAttr`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Nl80211SchedScanPlan(pub Vec<Nl80211SchedScanPlanAttr>);

impl Deref for Nl80211SchedScanPlan {
    type Target = Vec<Nl80211SchedScanPlanAttr>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for Nl80211SchedScanPlan
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let err = "Invalid NLA for NL80211_SCHED_SCAN_PLANS";
        let mut attrs = Vec::new();
        for nla in NlasIterator::new(buf.value()) {
            let nla = &nla.context(err)?;
            attrs.push(Nl80211SchedScanPlanAttr::parse(nla).context(err)?);
        }
        Ok(Self(attrs))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Nl80211SchedScanPlanAttr {
    /// Interval between scan iterations in seconds.
    Interval(u32),
    /// Number of scan iterations in this scan plan. The last scan plan
    /// must not specify this attribute because it will run infinitely. A value
    /// of zero is invalid as it will make the scan plan meaningless.
    Iterations(u32),
    Other(DefaultNla),
}

impl Nla for Nl80211SchedScanPlanAttr {
    fn value_len(&self) -> usize {
        match self {
            Self::Interval(_) => 4,
            Self::Iterations(_) => 4,
            Self::Other(v) => v.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Interval(d) | Self::Iterations(d) => write_u32(buffer, *d),
            Self::Other(attr) => attr.emit(buffer),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Interval(_) => NL80211_SCHED_SCAN_PLAN_INTERVAL,
            Self::Iterations(_) => NL80211_SCHED_SCAN_PLAN_ITERATIONS,
            Self::Other(attr) => attr.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for Nl80211SchedScanPlanAttr
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NL80211_SCHED_SCAN_PLAN_INTERVAL => {
                let err_msg = format!(
                    "Invalid NL80211_SCHED_SCAN_PLAN_INTERVAL value {payload:?}"
                );
                Self::Interval(parse_u32(payload).context(err_msg)?)
            }
            NL80211_SCHED_SCAN_PLAN_ITERATIONS => {
                let err_msg = format!(
                    "Invalid NL80211_SCHED_SCAN_PLAN_ITERATIONS value {payload:?}"
                );
                Self::Iterations(parse_u32(payload).context(err_msg)?)
            }
            _ => Self::Other(
                DefaultNla::parse(buf).context("invalid NLA (unknown kind)")?,
            ),
        })
    }
}
