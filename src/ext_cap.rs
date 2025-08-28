// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    DecodeError, Emitable, ErrorContext, Nla, NlaBuffer, NlasIterator,
    Parseable,
};

use crate::Nl80211Attr;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Nl80211ExtendedCapability(pub Vec<u8>);

//TODO: 802.11-2020 section `9.4.2.26 Extended Capabilities element` has
//      definition on every bit, we can expose getter and setter function
//      when required.
impl Nl80211ExtendedCapability {
    pub fn new(payload: &[u8]) -> Self {
        Self(payload.to_vec())
    }
}

impl Emitable for Nl80211ExtendedCapability {
    fn buffer_len(&self) -> usize {
        self.0.len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        if buffer.len() < self.0.len() {
            log::error!(
                "Buffer size is smaller than desired size {}",
                self.0.len()
            );
            return;
        }
        buffer[..self.0.len()].copy_from_slice(self.0.as_slice())
    }
}

impl std::ops::Deref for Nl80211ExtendedCapability {
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

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for Nl80211IfTypeExtCapas
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        let mut capas: Vec<Nl80211IfTypeExtCapa> = Vec::new();
        let err_msg =
            format!("Invalid NL80211_ATTR_IFTYPE_EXT_CAPA {payload:?}");
        for nla in NlasIterator::new(payload) {
            let nla = nla.context(err_msg.clone())?;
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
    fn value_len(&self) -> usize {
        self.attributes.as_slice().buffer_len()
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        self.attributes.as_slice().emit(buffer)
    }

    fn kind(&self) -> u16 {
        self.index
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for Nl80211IfTypeExtCapa
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let index = buf.kind();
        let payload = buf.value();
        let mut attributes: Vec<Nl80211Attr> = Vec::new();
        let err_msg =
            format!("Invalid NL80211_ATTR_IFTYPE_EXT_CAPA {payload:?}");
        for nla in NlasIterator::new(payload) {
            let nla = nla.context(err_msg.clone())?;
            attributes.push(Nl80211Attr::parse(&nla).context(err_msg.clone())?);
        }
        Ok(Self { index, attributes })
    }
}
