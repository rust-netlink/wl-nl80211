// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    parse_u8, DecodeError, DefaultNla, Emitable, ErrorContext, Nla, NlaBuffer,
    NlasIterator, Parseable,
};

const ETH_ALEN: usize = 6;
const NL80211_ATTR_MAC: u16 = 6;
const NL80211_ATTR_MLO_LINK_ID: u16 = 313;

#[derive(Debug, PartialEq, Eq, Clone)]
enum Nl80211MloLinkNla {
    Id(u8),
    Mac([u8; ETH_ALEN]),
    Other(DefaultNla),
}

impl Nla for Nl80211MloLinkNla {
    fn value_len(&self) -> usize {
        match self {
            Self::Id(_) => 1,
            Self::Mac(_) => ETH_ALEN,
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Id(_) => NL80211_ATTR_MLO_LINK_ID,
            Self::Mac(_) => NL80211_ATTR_MAC,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Id(d) => buffer[0] = *d,
            Self::Mac(s) => buffer.copy_from_slice(s),
            Self::Other(attr) => attr.emit(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for Nl80211MloLinkNla
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NL80211_ATTR_MLO_LINK_ID => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_MLO_LINK_ID value {payload:?}"
                );
                Self::Id(parse_u8(payload).context(err_msg)?)
            }
            NL80211_ATTR_MAC => Self::Mac(if payload.len() == ETH_ALEN {
                let mut ret = [0u8; ETH_ALEN];
                ret.copy_from_slice(&payload[..ETH_ALEN]);
                ret
            } else {
                return Err(format!(
                    "Invalid length of NL80211_ATTR_MAC, expected length {ETH_ALEN} got {payload:?}"
                )
                .into());
            }),
            _ => Self::Other(
                DefaultNla::parse(buf).context("invalid NLA (unknown kind)")?,
            ),
        })
    }
}

/// Multi-Link Operation
#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[non_exhaustive]
pub struct Nl80211MloLink {
    pub id: u8,
    pub mac: [u8; ETH_ALEN],
}

impl Nla for Nl80211MloLink {
    fn value_len(&self) -> usize {
        Vec::<Nl80211MloLinkNla>::from(self).as_slice().buffer_len()
    }

    fn kind(&self) -> u16 {
        self.id as u16 + 1
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        Vec::<Nl80211MloLinkNla>::from(self).as_slice().emit(buffer)
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for Nl80211MloLink
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let mut ret = Self::default();
        let payload = buf.value();
        let err_msg =
            format!("Invalid NL80211_ATTR_MLO_LINKS value {payload:?}");
        for nla in NlasIterator::new(payload) {
            let nla = &nla.context(err_msg.clone())?;
            match Nl80211MloLinkNla::parse(nla).context(err_msg.clone())? {
                Nl80211MloLinkNla::Id(d) => ret.id = d,
                Nl80211MloLinkNla::Mac(s) => ret.mac = s,
                Nl80211MloLinkNla::Other(attr) => {
                    log::warn!(
                        "Got unsupported NL80211_ATTR_MLO_LINKS value {attr:?}"
                    )
                }
            }
        }
        Ok(ret)
    }
}

impl From<&Nl80211MloLink> for Vec<Nl80211MloLinkNla> {
    fn from(link: &Nl80211MloLink) -> Self {
        vec![
            Nl80211MloLinkNla::Id(link.id),
            Nl80211MloLinkNla::Mac(link.mac),
        ]
    }
}
