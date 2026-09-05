// SPDX-License-Identifier: MIT

mod action_frame;
mod assoc;
mod auth;
mod capability;

use netlink_packet_core::{
    parse_u16, DecodeError, Emitable, ErrorContext, Nla, NlaBuffer,
    NlasIterator, Parseable,
};

use crate::{
    attr::NL80211_ATTR_FRAME_TYPE, bytes::write_u16, Nl80211InterfaceType,
};

pub use self::action_frame::{
    Ieee80211ActionFrame, Ieee80211ActionFrameBtmRequest,
    Ieee80211ActionFrameBtmResponse, Ieee80211ActionFrameNeighborReportRequest,
    Ieee80211ActionFrameNeighborReportResponse, Ieee80211ActionFrameOther,
    Ieee80211BtmCandidate, Ieee80211BtmRequest, Ieee80211BtmResponse,
    Ieee80211NeighborReportEntry, Ieee80211NeighborReportRequest,
    Ieee80211NeighborReportResponse,
};
pub use self::assoc::Ieee80211AssocRespFrame;
pub use self::auth::{
    Ieee80211AuthAlgorithm, Ieee80211AuthFrame, Ieee80211AuthFrameEppke,
    Ieee80211AuthFrameFastBssTransition, Ieee80211AuthFrameFilsPublicKey,
    Ieee80211AuthFrameFilsSharedKey, Ieee80211AuthFrameFilsSharedKeyPfs,
    Ieee80211AuthFrameIeee8021x, Ieee80211AuthFrameLeap,
    Ieee80211AuthFrameOpenSystem, Ieee80211AuthFrameOther,
    Ieee80211AuthFramePasn, Ieee80211AuthFrameSae, Ieee80211AuthFrameSharedKey,
    Ieee80211AuthFrameVendorSpecific,
};
pub use self::capability::Ieee80211CapabilityInfo;

/// Frame Control type/subtype mask (802.11-2020 §9.2.4.1.3, bits 2-7).
const FRAME_CTRL_TYPE_SUBTYPE_MASK: u16 = 0x00FC;

/// A parsed IEEE 802.11 management frame delivered by an nl80211 event.
///
/// Only full-frame codecs are represented as typed variants; unmodelled or
/// malformed management frames are kept losslessly in [`Other`](Self::Other).
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum Ieee80211Frame {
    /// Authentication management frame.
    Auth(Ieee80211AuthFrame),
    /// Action management frame.
    Action(Ieee80211ActionFrame),
    /// Any other management frame, kept as the raw wire bytes.
    Other {
        /// Frame Control field.
        frame_control: u16,
        /// Full frame bytes as received.
        raw: Vec<u8>,
    },
}

impl Ieee80211Frame {
    /// Parse a management frame delivered in `NL80211_ATTR_FRAME`.
    ///
    /// Unmodelled subtypes and malformed typed frames are returned as
    /// [`Other`](Self::Other) instead of being dropped.
    pub fn parse(data: &[u8]) -> Result<Self, DecodeError> {
        if data.len() < 2 {
            return Err(DecodeError::buffer_too_small(data.len(), 2));
        }
        let frame_control = u16::from_le_bytes([data[0], data[1]]);
        Ok(match frame_control & FRAME_CTRL_TYPE_SUBTYPE_MASK {
            IEEE80211_STYPE_AUTH => match Ieee80211AuthFrame::parse(data) {
                Ok(frame) => Self::Auth(frame),
                Err(_) => Self::Other {
                    frame_control,
                    raw: data.to_vec(),
                },
            },
            IEEE80211_STYPE_ACTION => match Ieee80211ActionFrame::parse(data) {
                Ok(frame) => Self::Action(frame),
                Err(_) => Self::Other {
                    frame_control,
                    raw: data.to_vec(),
                },
            },
            _ => Self::Other {
                frame_control,
                raw: data.to_vec(),
            },
        })
    }

    /// Serialize this frame back into raw 802.11 management frame bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Auth(frame) => frame.to_bytes(),
            Self::Action(frame) => frame.to_bytes(),
            Self::Other { raw, .. } => raw.clone(),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct Nl80211IfaceFrameType {
    pub iface_type: Nl80211InterfaceType,
    pub attributes: Vec<Ieee80211FrameType>,
}

impl Nla for Nl80211IfaceFrameType {
    fn value_len(&self) -> usize {
        self.attributes.as_slice().buffer_len()
    }

    fn kind(&self) -> u16 {
        u32::from(self.iface_type) as u16
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        self.attributes.as_slice().emit(buffer)
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for Nl80211IfaceFrameType
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        let iface_type = Nl80211InterfaceType::from(buf.kind() as u32);
        let err_msg = format!("Invalid NL80211_IFACE_COMB_LIMITS {payload:?}");
        let mut attributes = Vec::new();
        for nla in NlasIterator::new(payload) {
            let nla = &nla.context(err_msg.clone())?;
            // We are discarding other kind of NLA, but linux kernel
            // most likely will not add new NLA type for
            // NL80211_ATTR_TX_FRAME_TYPES.
            if nla.kind() == NL80211_ATTR_FRAME_TYPE {
                attributes.push(Ieee80211FrameType::from(
                    parse_u16(nla.value()).context(format!(
                        "Invalid NL80211_ATTR_FRAME_TYPE {:?}",
                        nla.value()
                    ))?,
                ));
            }
        }
        Ok(Self {
            iface_type,
            attributes,
        })
    }
}

const IEEE80211_FTYPE_MGMT: u8 = 0x00;
const IEEE80211_FTYPE_CTL: u8 = 0x04;
const IEEE80211_FTYPE_DATA: u8 = 0x08;
const IEEE80211_FTYPE_EXT: u8 = 0x0c;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum Ieee80211FrameType {
    Management(Ieee80211FrameTypeMgmt),
    Control(Ieee80211FrameTypeCtl),
    Data(Ieee80211FrameTypeData),
    Extension(Ieee80211FrameTypeExt),
    Other(u16),
}

impl Nla for Ieee80211FrameType {
    fn value_len(&self) -> usize {
        2
    }

    fn kind(&self) -> u16 {
        NL80211_ATTR_FRAME_TYPE
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        write_u16(buffer, u16::from(*self))
    }
}

impl From<u16> for Ieee80211FrameType {
    fn from(d: u16) -> Self {
        let frame_type = (d & 0xf) as u8;
        let sub_type = d - frame_type as u16;
        match frame_type {
            IEEE80211_FTYPE_MGMT => {
                Self::Management(Ieee80211FrameTypeMgmt::from(sub_type))
            }
            IEEE80211_FTYPE_CTL => {
                Self::Control(Ieee80211FrameTypeCtl::from(sub_type))
            }
            IEEE80211_FTYPE_DATA => {
                Self::Data(Ieee80211FrameTypeData::from(sub_type))
            }
            IEEE80211_FTYPE_EXT => {
                Self::Extension(Ieee80211FrameTypeExt::from(sub_type))
            }
            _ => Self::Other(d),
        }
    }
}

impl From<Ieee80211FrameType> for u16 {
    fn from(v: Ieee80211FrameType) -> u16 {
        match v {
            Ieee80211FrameType::Management(s) => {
                IEEE80211_FTYPE_MGMT as u16 | u16::from(s)
            }
            Ieee80211FrameType::Control(s) => {
                IEEE80211_FTYPE_CTL as u16 | u16::from(s)
            }
            Ieee80211FrameType::Data(s) => {
                IEEE80211_FTYPE_DATA as u16 | u16::from(s)
            }
            Ieee80211FrameType::Extension(s) => {
                IEEE80211_FTYPE_EXT as u16 | u16::from(s)
            }
            Ieee80211FrameType::Other(d) => d,
        }
    }
}

const IEEE80211_STYPE_ASSOC_REQ: u16 = 0x0000;
const IEEE80211_STYPE_ASSOC_RESP: u16 = 0x0010;
const IEEE80211_STYPE_REASSOC_REQ: u16 = 0x0020;
const IEEE80211_STYPE_REASSOC_RESP: u16 = 0x0030;
const IEEE80211_STYPE_PROBE_REQ: u16 = 0x0040;
const IEEE80211_STYPE_PROBE_RESP: u16 = 0x0050;
const IEEE80211_STYPE_TIMING_ADV: u16 = 0x0060;
const IEEE80211_STYPE_BEACON: u16 = 0x0080;
const IEEE80211_STYPE_ATIM: u16 = 0x0090;
const IEEE80211_STYPE_DISASSOC: u16 = 0x00A0;
const IEEE80211_STYPE_AUTH: u16 = 0x00B0;
const IEEE80211_STYPE_DEAUTH: u16 = 0x00C0;
const IEEE80211_STYPE_ACTION: u16 = 0x00D0;
const IEEE80211_STYPE_ACTION_NO_ACK: u16 = 0x00E0;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum Ieee80211FrameTypeMgmt {
    AssocReq,
    AssocResp,
    ReassocReq,
    ReassocResp,
    ProbeReq,
    ProbeResp,
    TimingAdvertisement,
    Beacon,
    Atim,
    Disassoc,
    Auth,
    Deauth,
    Action,
    ActionNoAck,
    Other(u16),
}

impl From<u16> for Ieee80211FrameTypeMgmt {
    fn from(d: u16) -> Self {
        match d {
            IEEE80211_STYPE_ASSOC_REQ => Self::AssocReq,
            IEEE80211_STYPE_ASSOC_RESP => Self::AssocResp,
            IEEE80211_STYPE_REASSOC_REQ => Self::ReassocReq,
            IEEE80211_STYPE_REASSOC_RESP => Self::ReassocResp,
            IEEE80211_STYPE_PROBE_REQ => Self::ProbeReq,
            IEEE80211_STYPE_PROBE_RESP => Self::ProbeResp,
            IEEE80211_STYPE_TIMING_ADV => Self::TimingAdvertisement,
            IEEE80211_STYPE_BEACON => Self::Beacon,
            IEEE80211_STYPE_ATIM => Self::Atim,
            IEEE80211_STYPE_DISASSOC => Self::Disassoc,
            IEEE80211_STYPE_AUTH => Self::Auth,
            IEEE80211_STYPE_DEAUTH => Self::Deauth,
            IEEE80211_STYPE_ACTION => Self::Action,
            IEEE80211_STYPE_ACTION_NO_ACK => Self::ActionNoAck,
            _ => Self::Other(d),
        }
    }
}

impl From<Ieee80211FrameTypeMgmt> for u16 {
    fn from(v: Ieee80211FrameTypeMgmt) -> u16 {
        match v {
            Ieee80211FrameTypeMgmt::AssocReq => IEEE80211_STYPE_ASSOC_REQ,
            Ieee80211FrameTypeMgmt::AssocResp => IEEE80211_STYPE_ASSOC_RESP,
            Ieee80211FrameTypeMgmt::ReassocReq => IEEE80211_STYPE_REASSOC_REQ,
            Ieee80211FrameTypeMgmt::ReassocResp => IEEE80211_STYPE_REASSOC_RESP,
            Ieee80211FrameTypeMgmt::ProbeReq => IEEE80211_STYPE_PROBE_REQ,
            Ieee80211FrameTypeMgmt::ProbeResp => IEEE80211_STYPE_PROBE_RESP,
            Ieee80211FrameTypeMgmt::TimingAdvertisement => {
                IEEE80211_STYPE_TIMING_ADV
            }
            Ieee80211FrameTypeMgmt::Beacon => IEEE80211_STYPE_BEACON,
            Ieee80211FrameTypeMgmt::Atim => IEEE80211_STYPE_ATIM,
            Ieee80211FrameTypeMgmt::Disassoc => IEEE80211_STYPE_DISASSOC,
            Ieee80211FrameTypeMgmt::Auth => IEEE80211_STYPE_AUTH,
            Ieee80211FrameTypeMgmt::Deauth => IEEE80211_STYPE_DEAUTH,
            Ieee80211FrameTypeMgmt::Action => IEEE80211_STYPE_ACTION,
            Ieee80211FrameTypeMgmt::ActionNoAck => {
                IEEE80211_STYPE_ACTION_NO_ACK
            }
            Ieee80211FrameTypeMgmt::Other(d) => d,
        }
    }
}

const IEEE80211_STYPE_TRIGGER: u16 = 0x0020;
const IEEE80211_STYPE_TACK: u16 = 0x0030;
const IEEE80211_STYPE_BEAMFORMING_REPORT_POLL: u16 = 0x0040;
const IEEE80211_STYPE_VHT_HE_NDP_ANNOUNCEMENT: u16 = 0x0050;
const IEEE80211_STYPE_CTL_EXT: u16 = 0x0060;
const IEEE80211_STYPE_CTL_WRAPPER: u16 = 0x0070;
const IEEE80211_STYPE_BACK_REQ: u16 = 0x0080;
const IEEE80211_STYPE_BACK: u16 = 0x0090;
const IEEE80211_STYPE_PSPOLL: u16 = 0x00A0;
const IEEE80211_STYPE_RTS: u16 = 0x00B0;
const IEEE80211_STYPE_CTS: u16 = 0x00C0;
const IEEE80211_STYPE_ACK: u16 = 0x00D0;
const IEEE80211_STYPE_CFEND: u16 = 0x00E0;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum Ieee80211FrameTypeCtl {
    Trigger,
    Tack,
    BeamformingReportPoll,
    VhtHeNdpAnnouncement,
    CtlExt,
    ControlWrapper,
    BackReq,
    Back,
    Pspoll,
    Rts,
    Cts,
    Ack,
    Cfend,
    Other(u16),
}

impl From<u16> for Ieee80211FrameTypeCtl {
    fn from(d: u16) -> Self {
        match d {
            IEEE80211_STYPE_TRIGGER => Self::Trigger,
            IEEE80211_STYPE_TACK => Self::Tack,
            IEEE80211_STYPE_BEAMFORMING_REPORT_POLL => {
                Self::BeamformingReportPoll
            }
            IEEE80211_STYPE_VHT_HE_NDP_ANNOUNCEMENT => {
                Self::VhtHeNdpAnnouncement
            }
            IEEE80211_STYPE_CTL_EXT => Self::CtlExt,
            IEEE80211_STYPE_CTL_WRAPPER => Self::ControlWrapper,
            IEEE80211_STYPE_BACK_REQ => Self::BackReq,
            IEEE80211_STYPE_BACK => Self::Back,
            IEEE80211_STYPE_PSPOLL => Self::Pspoll,
            IEEE80211_STYPE_RTS => Self::Rts,
            IEEE80211_STYPE_CTS => Self::Cts,
            IEEE80211_STYPE_ACK => Self::Ack,
            IEEE80211_STYPE_CFEND => Self::Cfend,
            _ => Self::Other(d),
        }
    }
}

impl From<Ieee80211FrameTypeCtl> for u16 {
    fn from(v: Ieee80211FrameTypeCtl) -> u16 {
        match v {
            Ieee80211FrameTypeCtl::Trigger => IEEE80211_STYPE_TRIGGER,
            Ieee80211FrameTypeCtl::Tack => IEEE80211_STYPE_TACK,
            Ieee80211FrameTypeCtl::BeamformingReportPoll => {
                IEEE80211_STYPE_BEAMFORMING_REPORT_POLL
            }
            Ieee80211FrameTypeCtl::VhtHeNdpAnnouncement => {
                IEEE80211_STYPE_VHT_HE_NDP_ANNOUNCEMENT
            }
            Ieee80211FrameTypeCtl::CtlExt => IEEE80211_STYPE_CTL_EXT,
            Ieee80211FrameTypeCtl::ControlWrapper => {
                IEEE80211_STYPE_CTL_WRAPPER
            }
            Ieee80211FrameTypeCtl::BackReq => IEEE80211_STYPE_BACK_REQ,
            Ieee80211FrameTypeCtl::Back => IEEE80211_STYPE_BACK,
            Ieee80211FrameTypeCtl::Pspoll => IEEE80211_STYPE_PSPOLL,
            Ieee80211FrameTypeCtl::Rts => IEEE80211_STYPE_RTS,
            Ieee80211FrameTypeCtl::Cts => IEEE80211_STYPE_CTS,
            Ieee80211FrameTypeCtl::Ack => IEEE80211_STYPE_ACK,
            Ieee80211FrameTypeCtl::Cfend => IEEE80211_STYPE_CFEND,
            Ieee80211FrameTypeCtl::Other(d) => d,
        }
    }
}

const IEEE80211_STYPE_DATA: u16 = 0x0000;
const IEEE80211_STYPE_EBCS_DATA: u16 = 0x0010;
const IEEE80211_STYPE_NULLFUNC: u16 = 0x0040;
const IEEE80211_STYPE_QOS_DATA: u16 = 0x0080;
const IEEE80211_STYPE_QOS_DATA_CFACK: u16 = 0x0090;
const IEEE80211_STYPE_QOS_DATA_CFPOLL: u16 = 0x00A0;
const IEEE80211_STYPE_QOS_DATA_CFACKPOLL: u16 = 0x00B0;
const IEEE80211_STYPE_QOS_NULLFUNC: u16 = 0x00C0;
const IEEE80211_STYPE_QOS_CFPOLL: u16 = 0x00E0;
const IEEE80211_STYPE_QOS_CFACKPOLL: u16 = 0x00F0;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum Ieee80211FrameTypeData {
    Data,
    EbcData,
    Nullfunc,
    QosData,
    QosDataCfack,
    QosDataCfpoll,
    QosDataCfackpoll,
    QosNullfunc,
    QosCfpoll,
    QosCfackpoll,
    Other(u16),
}

impl From<u16> for Ieee80211FrameTypeData {
    fn from(d: u16) -> Self {
        match d {
            IEEE80211_STYPE_DATA => Self::Data,
            IEEE80211_STYPE_EBCS_DATA => Self::EbcData,
            IEEE80211_STYPE_NULLFUNC => Self::Nullfunc,
            IEEE80211_STYPE_QOS_DATA => Self::QosData,
            IEEE80211_STYPE_QOS_DATA_CFACK => Self::QosDataCfack,
            IEEE80211_STYPE_QOS_DATA_CFPOLL => Self::QosDataCfpoll,
            IEEE80211_STYPE_QOS_DATA_CFACKPOLL => Self::QosDataCfackpoll,
            IEEE80211_STYPE_QOS_NULLFUNC => Self::QosNullfunc,
            IEEE80211_STYPE_QOS_CFPOLL => Self::QosCfpoll,
            IEEE80211_STYPE_QOS_CFACKPOLL => Self::QosCfackpoll,
            _ => Self::Other(d),
        }
    }
}

impl From<Ieee80211FrameTypeData> for u16 {
    fn from(v: Ieee80211FrameTypeData) -> u16 {
        match v {
            Ieee80211FrameTypeData::Data => IEEE80211_STYPE_DATA,
            Ieee80211FrameTypeData::EbcData => IEEE80211_STYPE_EBCS_DATA,
            Ieee80211FrameTypeData::Nullfunc => IEEE80211_STYPE_NULLFUNC,
            Ieee80211FrameTypeData::QosData => IEEE80211_STYPE_QOS_DATA,
            Ieee80211FrameTypeData::QosDataCfack => {
                IEEE80211_STYPE_QOS_DATA_CFACK
            }
            Ieee80211FrameTypeData::QosDataCfpoll => {
                IEEE80211_STYPE_QOS_DATA_CFPOLL
            }
            Ieee80211FrameTypeData::QosDataCfackpoll => {
                IEEE80211_STYPE_QOS_DATA_CFACKPOLL
            }
            Ieee80211FrameTypeData::QosNullfunc => IEEE80211_STYPE_QOS_NULLFUNC,
            Ieee80211FrameTypeData::QosCfpoll => IEEE80211_STYPE_QOS_CFPOLL,
            Ieee80211FrameTypeData::QosCfackpoll => {
                IEEE80211_STYPE_QOS_CFACKPOLL
            }
            Ieee80211FrameTypeData::Other(d) => d,
        }
    }
}

const IEEE80211_STYPE_DMG_BEACON: u16 = 0x0000;
const IEEE80211_STYPE_S1G_BEACON: u16 = 0x0010;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum Ieee80211FrameTypeExt {
    DmgBeacon,
    S1gBeacon,
    Other(u16),
}

impl From<u16> for Ieee80211FrameTypeExt {
    fn from(d: u16) -> Self {
        match d {
            IEEE80211_STYPE_DMG_BEACON => Self::DmgBeacon,
            IEEE80211_STYPE_S1G_BEACON => Self::S1gBeacon,
            _ => Self::Other(d),
        }
    }
}

impl From<Ieee80211FrameTypeExt> for u16 {
    fn from(v: Ieee80211FrameTypeExt) -> u16 {
        match v {
            Ieee80211FrameTypeExt::DmgBeacon => IEEE80211_STYPE_DMG_BEACON,
            Ieee80211FrameTypeExt::S1gBeacon => IEEE80211_STYPE_S1G_BEACON,
            Ieee80211FrameTypeExt::Other(d) => d,
        }
    }
}
