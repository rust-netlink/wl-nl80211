// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    DecodeError, Emitable, ErrorContext, NlasIterator, Parseable,
    ParseableParametrized,
};
use netlink_packet_generic::{GenlFamily, GenlHeader};

use crate::{Nl80211Attr, Nl80211Command};

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
        self.attributes.as_slice().buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.attributes.as_slice().emit(buffer)
    }
}

fn parse_nlas(buffer: &[u8]) -> Result<Vec<Nl80211Attr>, DecodeError> {
    let mut nlas = Vec::new();
    for nla in NlasIterator::new(buffer) {
        let error_msg = "Failed to parse nl80211 message attribute".to_string();
        let nla = &nla.context(error_msg.clone())?;
        nlas.push(Nl80211Attr::parse(nla).context(error_msg)?);
    }
    Ok(nlas)
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
