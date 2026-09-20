// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    DecodeError, Emitable, ErrorContext, NlasIterator, Parseable,
    ParseableParametrized,
};
use netlink_packet_generic::{GenlFamily, GenlHeader};

use crate::{Nl80211Attr, Nl80211Command};

/// A nl80211 message: the command and its attributes.
///
/// A received SSID is always stored as [`Nl80211Attr::SsidRaw`], the
/// [`Nl80211Attr::Ssid`] string view of it is included as well when the SSID
/// octets are valid UTF-8. When both are present only the raw attribute is
/// emitted, the string one is used when there is no raw attribute.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Nl80211Message {
    pub cmd: Nl80211Command,
    pub attributes: Vec<Nl80211Attr>,
}

impl GenlFamily for Nl80211Message {
    fn family_name() -> &'static str {
        "nl80211"
    }

    fn version(&self) -> u8 {
        1
    }

    fn command(&self) -> u8 {
        self.cmd.into()
    }
}

impl Emitable for Nl80211Message {
    fn buffer_len(&self) -> usize {
        self.attributes
            .iter()
            .filter(|attr| !ssid_string_is_overridden(attr, &self.attributes))
            .map(|attr| attr.buffer_len())
            .sum()
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut offset = 0;
        for attr in self
            .attributes
            .iter()
            .filter(|attr| !ssid_string_is_overridden(attr, &self.attributes))
        {
            attr.emit(&mut buffer[offset..offset + attr.buffer_len()]);
            offset += attr.buffer_len();
        }
    }
}

/// The UTF-8 string view of a raw SSID attribute, `None` when the SSID octets
/// are not valid UTF-8.
fn ssid_string_view(attr: &Nl80211Attr) -> Option<Nl80211Attr> {
    match attr {
        Nl80211Attr::SsidRaw(ssid) => std::str::from_utf8(ssid)
            .ok()
            .map(|ssid| Nl80211Attr::Ssid(ssid.to_string())),
        Nl80211Attr::ScanSsidsRaw(ssids) => ssids
            .iter()
            .map(|ssid| std::str::from_utf8(ssid).ok().map(str::to_string))
            .collect::<Option<Vec<String>>>()
            .map(Nl80211Attr::ScanSsids),
        _ => None,
    }
}

/// Whether `attr` is the string form of an SSID `attrs` also holds in its
/// raw form: the raw attribute wins, the string one is not emitted.
fn ssid_string_is_overridden(
    attr: &Nl80211Attr,
    attrs: &[Nl80211Attr],
) -> bool {
    match attr {
        Nl80211Attr::Ssid(_) => attrs
            .iter()
            .any(|attr| matches!(attr, Nl80211Attr::SsidRaw(_))),
        Nl80211Attr::ScanSsids(_) => attrs
            .iter()
            .any(|attr| matches!(attr, Nl80211Attr::ScanSsidsRaw(_))),
        _ => false,
    }
}

fn parse_nlas(buffer: &[u8]) -> Result<Vec<Nl80211Attr>, DecodeError> {
    let mut ret = Vec::new();
    for nla in NlasIterator::new(buffer) {
        let error_msg = "Failed to parse nl80211 message attribute".to_string();
        let nla = &nla.context(error_msg.clone())?;
        let attr = Nl80211Attr::parse(nla).context(error_msg)?;
        let view = ssid_string_view(&attr);
        ret.push(attr);
        // A received SSID is always stored raw, the `Ssid` string view of it
        // is added as well when the octets are valid UTF-8.
        if let Some(view) = view {
            ret.push(view);
        }
    }
    Ok(ret)
}

impl ParseableParametrized<[u8], GenlHeader> for Nl80211Message {
    fn parse_with_param(
        buffer: &[u8],
        header: GenlHeader,
    ) -> Result<Self, DecodeError> {
        let cmd = Nl80211Command::from(header.cmd);
        let attributes = parse_nlas(buffer)?;
        Ok(Self { cmd, attributes })
    }
}
