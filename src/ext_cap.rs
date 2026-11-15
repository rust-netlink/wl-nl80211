// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    DecodeError, Emitable, EncodeError, ErrorContext, Nla, NlaBuffer,
    NlasIterator, Parseable, append_bytes,
};

use crate::Nl80211Attr;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Ieee80211ExtendedCapability(pub Vec<u8>);

//TODO: 802.11-2020 section `9.4.2.26 Extended Capabilities element` has
//      definition on every bit, we can expose getter and setter function
//      when required.
impl Ieee80211ExtendedCapability {
    pub fn new(payload: &[u8]) -> Self {
        Self(payload.to_vec())
    }
}

impl Emitable for Ieee80211ExtendedCapability {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        append_bytes(out, self.0.as_slice());
        Ok(())
    }
}

impl std::ops::Deref for Ieee80211ExtendedCapability {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Nl80211IfTypeExtCapas(pub Vec<Nl80211IfTypeExtCapa>);

impl std::ops::Deref for Nl80211IfTypeExtCapas {
    type Target = Vec<Nl80211IfTypeExtCapa>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for Nl80211IfTypeExtCapas {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        let mut capas: Vec<Nl80211IfTypeExtCapa> = Vec::new();
        for nla in NlasIterator::new(payload)? {
            capas.push(Nl80211IfTypeExtCapa::parse(&nla)?);
        }
        Ok(Self(capas))
    }
}

impl From<&Vec<Nl80211IfTypeExtCapa>> for Nl80211IfTypeExtCapas {
    fn from(v: &Vec<Nl80211IfTypeExtCapa>) -> Self {
        Self(v.clone())
    }
}

impl From<Nl80211IfTypeExtCapas> for Vec<Nl80211IfTypeExtCapa> {
    fn from(v: Nl80211IfTypeExtCapas) -> Vec<Nl80211IfTypeExtCapa> {
        v.0
    }
}

// For linux kernel, NL80211_ATTR_IFTYPE_EXT_CAPA is indexing from 0 but
// `capa_start`, hence we expose the index to user in case they want to generate
// identical data as linux kernel does.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Nl80211IfTypeExtCapa {
    pub index: u16,
    pub attributes: Vec<Nl80211Attr>,
}

impl Nla for Nl80211IfTypeExtCapa {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        self.attributes.as_slice().emit(out)?;
        Ok(())
    }

    fn kind(&self) -> u16 {
        self.index
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for Nl80211IfTypeExtCapa {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let index = buf.kind();
        let payload = buf.value();
        let mut attributes: Vec<Nl80211Attr> = Vec::new();
        let err_msg =
            format!("Invalid NL80211_ATTR_IFTYPE_EXT_CAPA {payload:?}");
        for nla in NlasIterator::new(payload)? {
            attributes.push(Nl80211Attr::parse(&nla).context(err_msg.clone())?);
        }
        Ok(Self { index, attributes })
    }
}
