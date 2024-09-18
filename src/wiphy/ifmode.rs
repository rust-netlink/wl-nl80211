// SPDX-License-Identifier: MIT

use netlink_packet_utils::{
    nla::{Nla, NlaBuffer},
    DecodeError, Parseable,
};

const NL80211_IFTYPE_ADHOC: u16 = 1;
const NL80211_IFTYPE_STATION: u16 = 2;
const NL80211_IFTYPE_AP: u16 = 3;
const NL80211_IFTYPE_AP_VLAN: u16 = 4;
const NL80211_IFTYPE_WDS: u16 = 5;
const NL80211_IFTYPE_MONITOR: u16 = 6;
const NL80211_IFTYPE_MESH_POINT: u16 = 7;
const NL80211_IFTYPE_P2P_CLIENT: u16 = 8;
const NL80211_IFTYPE_P2P_GO: u16 = 9;
const NL80211_IFTYPE_P2P_DEVICE: u16 = 10;
const NL80211_IFTYPE_OCB: u16 = 11;
const NL80211_IFTYPE_NAN: u16 = 12;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Nl80211IfMode {
    Adhoc,
    Station,
    Ap,
    ApVlan,
    Wds,
    Monitor,
    MeshPoint,
    P2pClient,
    P2pGo,
    P2pDevice,
    Ocb,
    Nan,
    Other(u16),
}

impl From<u16> for Nl80211IfMode {
    fn from(d: u16) -> Self {
        match d {
            NL80211_IFTYPE_ADHOC => Self::Adhoc,
            NL80211_IFTYPE_STATION => Self::Station,
            NL80211_IFTYPE_AP => Self::Ap,
            NL80211_IFTYPE_AP_VLAN => Self::ApVlan,
            NL80211_IFTYPE_WDS => Self::Wds,
            NL80211_IFTYPE_MONITOR => Self::Monitor,
            NL80211_IFTYPE_MESH_POINT => Self::MeshPoint,
            NL80211_IFTYPE_P2P_CLIENT => Self::P2pClient,
            NL80211_IFTYPE_P2P_GO => Self::P2pGo,
            NL80211_IFTYPE_P2P_DEVICE => Self::P2pDevice,
            NL80211_IFTYPE_OCB => Self::Ocb,
            NL80211_IFTYPE_NAN => Self::Nan,
            _ => Self::Other(d),
        }
    }
}

impl From<Nl80211IfMode> for u16 {
    fn from(v: Nl80211IfMode) -> u16 {
        match v {
            Nl80211IfMode::Adhoc => NL80211_IFTYPE_ADHOC,
            Nl80211IfMode::Station => NL80211_IFTYPE_STATION,
            Nl80211IfMode::Ap => NL80211_IFTYPE_AP,
            Nl80211IfMode::ApVlan => NL80211_IFTYPE_AP_VLAN,
            Nl80211IfMode::Wds => NL80211_IFTYPE_WDS,
            Nl80211IfMode::Monitor => NL80211_IFTYPE_MONITOR,
            Nl80211IfMode::MeshPoint => NL80211_IFTYPE_MESH_POINT,
            Nl80211IfMode::P2pClient => NL80211_IFTYPE_P2P_CLIENT,
            Nl80211IfMode::P2pGo => NL80211_IFTYPE_P2P_GO,
            Nl80211IfMode::P2pDevice => NL80211_IFTYPE_P2P_DEVICE,
            Nl80211IfMode::Ocb => NL80211_IFTYPE_OCB,
            Nl80211IfMode::Nan => NL80211_IFTYPE_NAN,
            Nl80211IfMode::Other(d) => d,
        }
    }
}

impl Nla for Nl80211IfMode {
    fn value_len(&self) -> usize {
        0
    }

    fn kind(&self) -> u16 {
        match self {
            Nl80211IfMode::Adhoc => NL80211_IFTYPE_ADHOC,
            Nl80211IfMode::Station => NL80211_IFTYPE_STATION,
            Nl80211IfMode::Ap => NL80211_IFTYPE_AP,
            Nl80211IfMode::ApVlan => NL80211_IFTYPE_AP_VLAN,
            Nl80211IfMode::Wds => NL80211_IFTYPE_WDS,
            Nl80211IfMode::Monitor => NL80211_IFTYPE_MONITOR,
            Nl80211IfMode::MeshPoint => NL80211_IFTYPE_MESH_POINT,
            Nl80211IfMode::P2pClient => NL80211_IFTYPE_P2P_CLIENT,
            Nl80211IfMode::P2pGo => NL80211_IFTYPE_P2P_GO,
            Nl80211IfMode::P2pDevice => NL80211_IFTYPE_P2P_DEVICE,
            Nl80211IfMode::Ocb => NL80211_IFTYPE_OCB,
            Nl80211IfMode::Nan => NL80211_IFTYPE_NAN,
            Nl80211IfMode::Other(d) => *d,
        }
    }

    fn emit_value(&self, _buffer: &mut [u8]) {}
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for Nl80211IfMode
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        Ok(buf.kind().into())
    }
}
