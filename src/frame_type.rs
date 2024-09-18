// SPDX-License-Identifier: MIT

use anyhow::Context;
use netlink_packet_utils::{
    nla::{Nla, NlaBuffer, NlasIterator},
    parsers::parse_u16,
    DecodeError, Emitable, Parseable,
};

use crate::{bytes::write_u16, Nl80211InterfaceType};

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct Nl80211IfaceFrameType {
    pub iface_type: Nl80211InterfaceType,
    pub attributes: Vec<Nl80211FrameType>,
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

const NL80211_ATTR_FRAME_TYPE: u16 = 101;

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
                attributes.push(Nl80211FrameType::from(
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
pub enum Nl80211FrameType {
    Management(Nl80211FrameTypeMgmt),
    Control(Nl80211FrameTypeCtl),
    Data(Nl80211FrameTypeData),
    Extension(Nl80211FrameTypeExt),
    Other(u16),
}

impl Nla for Nl80211FrameType {
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

impl From<u16> for Nl80211FrameType {
    fn from(d: u16) -> Self {
        let frame_type = (d & 0xf) as u8;
        let sub_type = d - frame_type as u16;
        match frame_type {
            IEEE80211_FTYPE_MGMT => {
                Self::Management(Nl80211FrameTypeMgmt::from(sub_type))
            }
            IEEE80211_FTYPE_CTL => {
                Self::Control(Nl80211FrameTypeCtl::from(sub_type))
            }
            IEEE80211_FTYPE_DATA => {
                Self::Data(Nl80211FrameTypeData::from(sub_type))
            }
            IEEE80211_FTYPE_EXT => {
                Self::Extension(Nl80211FrameTypeExt::from(sub_type))
            }
            _ => Self::Other(d),
        }
    }
}

impl From<Nl80211FrameType> for u16 {
    fn from(v: Nl80211FrameType) -> u16 {
        match v {
            Nl80211FrameType::Management(s) => {
                IEEE80211_FTYPE_MGMT as u16 | u16::from(s)
            }
            Nl80211FrameType::Control(s) => {
                IEEE80211_FTYPE_CTL as u16 | u16::from(s)
            }
            Nl80211FrameType::Data(s) => {
                IEEE80211_FTYPE_DATA as u16 | u16::from(s)
            }
            Nl80211FrameType::Extension(s) => {
                IEEE80211_FTYPE_EXT as u16 | u16::from(s)
            }
            Nl80211FrameType::Other(d) => d,
        }
    }
}

const IEEE80211_STYPE_ASSOC_REQ: u16 = 0x0000;
const IEEE80211_STYPE_ASSOC_RESP: u16 = 0x0010;
const IEEE80211_STYPE_REASSOC_REQ: u16 = 0x0020;
const IEEE80211_STYPE_REASSOC_RESP: u16 = 0x0030;
const IEEE80211_STYPE_PROBE_REQ: u16 = 0x0040;
const IEEE80211_STYPE_PROBE_RESP: u16 = 0x0050;
const IEEE80211_STYPE_BEACON: u16 = 0x0080;
const IEEE80211_STYPE_ATIM: u16 = 0x0090;
const IEEE80211_STYPE_DISASSOC: u16 = 0x00A0;
const IEEE80211_STYPE_AUTH: u16 = 0x00B0;
const IEEE80211_STYPE_DEAUTH: u16 = 0x00C0;
const IEEE80211_STYPE_ACTION: u16 = 0x00D0;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum Nl80211FrameTypeMgmt {
    AssocReq,
    AssocResp,
    ReassocReq,
    ReassocResp,
    ProbeReq,
    ProbeResp,
    Beacon,
    Atim,
    Disassoc,
    Auth,
    Deauth,
    Action,
    Other(u16),
}

impl From<u16> for Nl80211FrameTypeMgmt {
    fn from(d: u16) -> Self {
        match d {
            IEEE80211_STYPE_ASSOC_REQ => Self::AssocReq,
            IEEE80211_STYPE_ASSOC_RESP => Self::AssocResp,
            IEEE80211_STYPE_REASSOC_REQ => Self::ReassocReq,
            IEEE80211_STYPE_REASSOC_RESP => Self::ReassocResp,
            IEEE80211_STYPE_PROBE_REQ => Self::ProbeReq,
            IEEE80211_STYPE_PROBE_RESP => Self::ProbeResp,
            IEEE80211_STYPE_BEACON => Self::Beacon,
            IEEE80211_STYPE_ATIM => Self::Atim,
            IEEE80211_STYPE_DISASSOC => Self::Disassoc,
            IEEE80211_STYPE_AUTH => Self::Auth,
            IEEE80211_STYPE_DEAUTH => Self::Deauth,
            IEEE80211_STYPE_ACTION => Self::Action,
            _ => Self::Other(d),
        }
    }
}

impl From<Nl80211FrameTypeMgmt> for u16 {
    fn from(v: Nl80211FrameTypeMgmt) -> u16 {
        match v {
            Nl80211FrameTypeMgmt::AssocReq => IEEE80211_STYPE_ASSOC_REQ,
            Nl80211FrameTypeMgmt::AssocResp => IEEE80211_STYPE_ASSOC_RESP,
            Nl80211FrameTypeMgmt::ReassocReq => IEEE80211_STYPE_REASSOC_REQ,
            Nl80211FrameTypeMgmt::ReassocResp => IEEE80211_STYPE_REASSOC_RESP,
            Nl80211FrameTypeMgmt::ProbeReq => IEEE80211_STYPE_PROBE_REQ,
            Nl80211FrameTypeMgmt::ProbeResp => IEEE80211_STYPE_PROBE_RESP,
            Nl80211FrameTypeMgmt::Beacon => IEEE80211_STYPE_BEACON,
            Nl80211FrameTypeMgmt::Atim => IEEE80211_STYPE_ATIM,
            Nl80211FrameTypeMgmt::Disassoc => IEEE80211_STYPE_DISASSOC,
            Nl80211FrameTypeMgmt::Auth => IEEE80211_STYPE_AUTH,
            Nl80211FrameTypeMgmt::Deauth => IEEE80211_STYPE_DEAUTH,
            Nl80211FrameTypeMgmt::Action => IEEE80211_STYPE_ACTION,
            Nl80211FrameTypeMgmt::Other(d) => d,
        }
    }
}

const IEEE80211_STYPE_TRIGGER: u16 = 0x0020;
const IEEE80211_STYPE_CTL_EXT: u16 = 0x0060;
const IEEE80211_STYPE_BACK_REQ: u16 = 0x0080;
const IEEE80211_STYPE_BACK: u16 = 0x0090;
const IEEE80211_STYPE_PSPOLL: u16 = 0x00A0;
const IEEE80211_STYPE_RTS: u16 = 0x00B0;
const IEEE80211_STYPE_CTS: u16 = 0x00C0;
const IEEE80211_STYPE_ACK: u16 = 0x00D0;
const IEEE80211_STYPE_CFEND: u16 = 0x00E0;
const IEEE80211_STYPE_CFENDACK: u16 = 0x00F0;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum Nl80211FrameTypeCtl {
    Trigger,
    CtlExt,
    BackReq,
    Back,
    Pspoll,
    Rts,
    Cts,
    Ack,
    Cfend,
    Cfendack,
    Other(u16),
}

impl From<u16> for Nl80211FrameTypeCtl {
    fn from(d: u16) -> Self {
        match d {
            IEEE80211_STYPE_TRIGGER => Self::Trigger,
            IEEE80211_STYPE_CTL_EXT => Self::CtlExt,
            IEEE80211_STYPE_BACK_REQ => Self::BackReq,
            IEEE80211_STYPE_BACK => Self::Back,
            IEEE80211_STYPE_PSPOLL => Self::Pspoll,
            IEEE80211_STYPE_RTS => Self::Rts,
            IEEE80211_STYPE_CTS => Self::Cts,
            IEEE80211_STYPE_ACK => Self::Ack,
            IEEE80211_STYPE_CFEND => Self::Cfend,
            IEEE80211_STYPE_CFENDACK => Self::Cfendack,
            _ => Self::Other(d),
        }
    }
}

impl From<Nl80211FrameTypeCtl> for u16 {
    fn from(v: Nl80211FrameTypeCtl) -> u16 {
        match v {
            Nl80211FrameTypeCtl::Trigger => IEEE80211_STYPE_TRIGGER,
            Nl80211FrameTypeCtl::CtlExt => IEEE80211_STYPE_CTL_EXT,
            Nl80211FrameTypeCtl::BackReq => IEEE80211_STYPE_BACK_REQ,
            Nl80211FrameTypeCtl::Back => IEEE80211_STYPE_BACK,
            Nl80211FrameTypeCtl::Pspoll => IEEE80211_STYPE_PSPOLL,
            Nl80211FrameTypeCtl::Rts => IEEE80211_STYPE_RTS,
            Nl80211FrameTypeCtl::Cts => IEEE80211_STYPE_CTS,
            Nl80211FrameTypeCtl::Ack => IEEE80211_STYPE_ACK,
            Nl80211FrameTypeCtl::Cfend => IEEE80211_STYPE_CFEND,
            Nl80211FrameTypeCtl::Cfendack => IEEE80211_STYPE_CFENDACK,
            Nl80211FrameTypeCtl::Other(d) => d,
        }
    }
}

const IEEE80211_STYPE_DATA: u16 = 0x0000;
const IEEE80211_STYPE_DATA_CFACK: u16 = 0x0010;
const IEEE80211_STYPE_DATA_CFPOLL: u16 = 0x0020;
const IEEE80211_STYPE_DATA_CFACKPOLL: u16 = 0x0030;
const IEEE80211_STYPE_NULLFUNC: u16 = 0x0040;
const IEEE80211_STYPE_CFACK: u16 = 0x0050;
const IEEE80211_STYPE_CFPOLL: u16 = 0x0060;
const IEEE80211_STYPE_CFACKPOLL: u16 = 0x0070;
const IEEE80211_STYPE_QOS_DATA: u16 = 0x0080;
const IEEE80211_STYPE_QOS_DATA_CFACK: u16 = 0x0090;
const IEEE80211_STYPE_QOS_DATA_CFPOLL: u16 = 0x00A0;
const IEEE80211_STYPE_QOS_DATA_CFACKPOLL: u16 = 0x00B0;
const IEEE80211_STYPE_QOS_NULLFUNC: u16 = 0x00C0;
const IEEE80211_STYPE_QOS_CFACK: u16 = 0x00D0;
const IEEE80211_STYPE_QOS_CFPOLL: u16 = 0x00E0;
const IEEE80211_STYPE_QOS_CFACKPOLL: u16 = 0x00F0;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum Nl80211FrameTypeData {
    Data,
    DataCfack,
    DataCfpoll,
    DataCfackpoll,
    Nullfunc,
    Cfack,
    Cfpoll,
    Cfackpoll,
    QosData,
    QosDataCfack,
    QosDataCfpoll,
    QosDataCfackpoll,
    QosNullfunc,
    QosCfack,
    QosCfpoll,
    QosCfackpoll,
    Other(u16),
}

impl From<u16> for Nl80211FrameTypeData {
    fn from(d: u16) -> Self {
        match d {
            IEEE80211_STYPE_DATA => Self::Data,
            IEEE80211_STYPE_DATA_CFACK => Self::DataCfack,
            IEEE80211_STYPE_DATA_CFPOLL => Self::DataCfpoll,
            IEEE80211_STYPE_DATA_CFACKPOLL => Self::DataCfackpoll,
            IEEE80211_STYPE_NULLFUNC => Self::Nullfunc,
            IEEE80211_STYPE_CFACK => Self::Cfack,
            IEEE80211_STYPE_CFPOLL => Self::Cfpoll,
            IEEE80211_STYPE_CFACKPOLL => Self::Cfackpoll,
            IEEE80211_STYPE_QOS_DATA => Self::QosData,
            IEEE80211_STYPE_QOS_DATA_CFACK => Self::QosDataCfack,
            IEEE80211_STYPE_QOS_DATA_CFPOLL => Self::QosDataCfpoll,
            IEEE80211_STYPE_QOS_DATA_CFACKPOLL => Self::QosDataCfackpoll,
            IEEE80211_STYPE_QOS_NULLFUNC => Self::QosNullfunc,
            IEEE80211_STYPE_QOS_CFACK => Self::QosCfack,
            IEEE80211_STYPE_QOS_CFPOLL => Self::QosCfpoll,
            IEEE80211_STYPE_QOS_CFACKPOLL => Self::QosCfackpoll,
            _ => Self::Other(d),
        }
    }
}

impl From<Nl80211FrameTypeData> for u16 {
    fn from(v: Nl80211FrameTypeData) -> u16 {
        match v {
            Nl80211FrameTypeData::Data => IEEE80211_STYPE_DATA,
            Nl80211FrameTypeData::DataCfack => IEEE80211_STYPE_DATA_CFACK,
            Nl80211FrameTypeData::DataCfpoll => IEEE80211_STYPE_DATA_CFPOLL,
            Nl80211FrameTypeData::DataCfackpoll => {
                IEEE80211_STYPE_DATA_CFACKPOLL
            }
            Nl80211FrameTypeData::Nullfunc => IEEE80211_STYPE_NULLFUNC,
            Nl80211FrameTypeData::Cfack => IEEE80211_STYPE_CFACK,
            Nl80211FrameTypeData::Cfpoll => IEEE80211_STYPE_CFPOLL,
            Nl80211FrameTypeData::Cfackpoll => IEEE80211_STYPE_CFACKPOLL,
            Nl80211FrameTypeData::QosData => IEEE80211_STYPE_QOS_DATA,
            Nl80211FrameTypeData::QosDataCfack => {
                IEEE80211_STYPE_QOS_DATA_CFACK
            }
            Nl80211FrameTypeData::QosDataCfpoll => {
                IEEE80211_STYPE_QOS_DATA_CFPOLL
            }
            Nl80211FrameTypeData::QosDataCfackpoll => {
                IEEE80211_STYPE_QOS_DATA_CFACKPOLL
            }
            Nl80211FrameTypeData::QosNullfunc => IEEE80211_STYPE_QOS_NULLFUNC,
            Nl80211FrameTypeData::QosCfack => IEEE80211_STYPE_QOS_CFACK,
            Nl80211FrameTypeData::QosCfpoll => IEEE80211_STYPE_QOS_CFPOLL,
            Nl80211FrameTypeData::QosCfackpoll => IEEE80211_STYPE_QOS_CFACKPOLL,
            Nl80211FrameTypeData::Other(d) => d,
        }
    }
}

const IEEE80211_STYPE_DMG_BEACON: u16 = 0x0000;
const IEEE80211_STYPE_S1G_BEACON: u16 = 0x0010;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum Nl80211FrameTypeExt {
    DmgBeacon,
    S1gBeacon,
    Other(u16),
}

impl From<u16> for Nl80211FrameTypeExt {
    fn from(d: u16) -> Self {
        match d {
            IEEE80211_STYPE_DMG_BEACON => Self::DmgBeacon,
            IEEE80211_STYPE_S1G_BEACON => Self::S1gBeacon,
            _ => Self::Other(d),
        }
    }
}

impl From<Nl80211FrameTypeExt> for u16 {
    fn from(v: Nl80211FrameTypeExt) -> u16 {
        match v {
            Nl80211FrameTypeExt::DmgBeacon => IEEE80211_STYPE_DMG_BEACON,
            Nl80211FrameTypeExt::S1gBeacon => IEEE80211_STYPE_S1G_BEACON,
            Nl80211FrameTypeExt::Other(d) => d,
        }
    }
}
