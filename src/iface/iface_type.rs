// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    parse_u32, DecodeError, ErrorContext, Nla, NlasIterator,
};

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct Nl80211InterfaceTypes(pub(crate) Vec<Nl80211InterfaceType>);

impl std::ops::Deref for Nl80211InterfaceTypes {
    type Target = Vec<Nl80211InterfaceType>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<&Vec<Nl80211InterfaceType>> for Nl80211InterfaceTypes {
    fn from(iface_types: &Vec<Nl80211InterfaceType>) -> Self {
        Self(iface_types.to_vec())
    }
}

impl From<Nl80211InterfaceTypes> for Vec<Nl80211InterfaceType> {
    fn from(iface_types: Nl80211InterfaceTypes) -> Self {
        iface_types.0
    }
}

impl Nl80211InterfaceTypes {
    pub fn parse(payload: &[u8], kind: &str) -> Result<Self, DecodeError> {
        let mut iface_types: Vec<Nl80211InterfaceType> = Vec::new();
        for nla in NlasIterator::new(payload) {
            let error_msg = format!("Invalid {kind}: {nla:?}");
            let nla = &nla.context(error_msg.clone())?;
            iface_types.push(Nl80211InterfaceType::from(nla.kind() as u32));
        }
        Ok(Self(iface_types))
    }
}

const NL80211_IFTYPE_UNSPECIFIED: u32 = 0;
const NL80211_IFTYPE_ADHOC: u32 = 1;
const NL80211_IFTYPE_STATION: u32 = 2;
const NL80211_IFTYPE_AP: u32 = 3;
const NL80211_IFTYPE_AP_VLAN: u32 = 4;
const NL80211_IFTYPE_WDS: u32 = 5;
const NL80211_IFTYPE_MONITOR: u32 = 6;
const NL80211_IFTYPE_MESH_POINT: u32 = 7;
const NL80211_IFTYPE_P2P_CLIENT: u32 = 8;
const NL80211_IFTYPE_P2P_GO: u32 = 9;
const NL80211_IFTYPE_P2P_DEVICE: u32 = 10;
const NL80211_IFTYPE_OCB: u32 = 11;
const NL80211_IFTYPE_NAN: u32 = 12;

// Linux kernel data type `enum nl80211_iftype`
/// (virtual) interface types
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Nl80211InterfaceType {
    /// unspecified type, driver decides
    Unspecified,
    /// Independent BSS member, also known as IBSS
    Adhoc,
    /// Managed BSS member, also known as managed
    Station,
    /// Access point
    Ap,
    /// VLAN interface for access points; VLAN interfaces are a bit special in
    /// that they must always be tied to a pre-existing AP type interface.
    ApVlan,
    /// wireless distribution interface
    Wds,
    /// Monitor interface receiving all frames
    Monitor,
    /// Mesh point
    MeshPoint,
    /// P2P client
    P2pClient,
    /// P2P group owner
    P2pGo,
    /// P2P device interface type, this is not a netdev
    P2pDevice,
    /// Outside Context of a BSS, This mode corresponds to the MIB variable
    /// dot11OCBActivated=true
    Ocb,
    /// NAN device interface type (not a netdev)
    Nan,
    Other(u32),
}

impl Nl80211InterfaceType {
    pub const LENGTH: usize = 4;

    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        Ok(parse_u32(payload)
            .context(format!("Invalid Nl80211InterfaceType data {payload:?}"))?
            .into())
    }
}

impl Nla for Nl80211InterfaceType {
    fn value_len(&self) -> usize {
        Self::LENGTH
    }

    fn emit_value(&self, _buffer: &mut [u8]) {}

    fn kind(&self) -> u16 {
        u32::from(*self) as u16
    }
}

impl From<u32> for Nl80211InterfaceType {
    fn from(d: u32) -> Self {
        match d {
            NL80211_IFTYPE_UNSPECIFIED => Self::Unspecified,
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

impl From<Nl80211InterfaceType> for u32 {
    fn from(v: Nl80211InterfaceType) -> u32 {
        match v {
            Nl80211InterfaceType::Unspecified => NL80211_IFTYPE_UNSPECIFIED,
            Nl80211InterfaceType::Adhoc => NL80211_IFTYPE_ADHOC,
            Nl80211InterfaceType::Station => NL80211_IFTYPE_STATION,
            Nl80211InterfaceType::Ap => NL80211_IFTYPE_AP,
            Nl80211InterfaceType::ApVlan => NL80211_IFTYPE_AP_VLAN,
            Nl80211InterfaceType::Wds => NL80211_IFTYPE_WDS,
            Nl80211InterfaceType::Monitor => NL80211_IFTYPE_MONITOR,
            Nl80211InterfaceType::MeshPoint => NL80211_IFTYPE_MESH_POINT,
            Nl80211InterfaceType::P2pClient => NL80211_IFTYPE_P2P_CLIENT,
            Nl80211InterfaceType::P2pGo => NL80211_IFTYPE_P2P_GO,
            Nl80211InterfaceType::P2pDevice => NL80211_IFTYPE_P2P_DEVICE,
            Nl80211InterfaceType::Ocb => NL80211_IFTYPE_OCB,
            Nl80211InterfaceType::Nan => NL80211_IFTYPE_NAN,
            Nl80211InterfaceType::Other(d) => d,
        }
    }
}
