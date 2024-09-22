// SPDX-License-Identifier: MIT

use anyhow::Context;
use netlink_packet_generic::{GenlFamily, GenlHeader};
use netlink_packet_utils::{
    nla::NlasIterator, DecodeError, Emitable, Parseable, ParseableParametrized,
};

use crate::attr::Nl80211Attr;

const NL80211_CMD_GET_WIPHY: u8 = 1;
const NL80211_CMD_NEW_WIPHY: u8 = 3;
const NL80211_CMD_GET_INTERFACE: u8 = 5;
const NL80211_CMD_NEW_INTERFACE: u8 = 7;
const NL80211_CMD_GET_STATION: u8 = 17;
const NL80211_CMD_NEW_STATION: u8 = 19;
const NL80211_CMD_GET_SCAN: u8 = 32;
const NL80211_CMD_NEW_SCAN_RESULTS: u8 = 34;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Nl80211Cmd {
    InterfaceGet,
    InterfaceNew,
    StationGet,
    StationNew,
    WiphyGet,
    WiphyNew,
    ScanGet,
}

impl From<Nl80211Cmd> for u8 {
    fn from(cmd: Nl80211Cmd) -> Self {
        match cmd {
            Nl80211Cmd::InterfaceGet => NL80211_CMD_GET_INTERFACE,
            Nl80211Cmd::InterfaceNew => NL80211_CMD_NEW_INTERFACE,
            Nl80211Cmd::StationGet => NL80211_CMD_GET_STATION,
            Nl80211Cmd::StationNew => NL80211_CMD_NEW_STATION,
            Nl80211Cmd::WiphyGet => NL80211_CMD_GET_WIPHY,
            Nl80211Cmd::WiphyNew => NL80211_CMD_NEW_WIPHY,
            Nl80211Cmd::ScanGet => NL80211_CMD_GET_SCAN,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Nl80211Message {
    pub cmd: Nl80211Cmd,
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

impl Nl80211Message {
    pub fn new_interface_get() -> Self {
        Nl80211Message {
            cmd: Nl80211Cmd::InterfaceGet,
            attributes: vec![],
        }
    }

    pub fn new_station_get(attributes: Vec<Nl80211Attr>) -> Self {
        Nl80211Message {
            cmd: Nl80211Cmd::StationGet,
            attributes,
        }
    }

    pub fn new_wiphy_get() -> Self {
        Nl80211Message {
            cmd: Nl80211Cmd::WiphyGet,
            attributes: vec![Nl80211Attr::SplitWiphyDump],
        }
    }

    pub fn new_scan_get(attributes: Vec<Nl80211Attr>) -> Self {
        Self {
            cmd: Nl80211Cmd::ScanGet,
            attributes,
        }
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
        Ok(match header.cmd {
            NL80211_CMD_NEW_INTERFACE => Self {
                cmd: Nl80211Cmd::InterfaceNew,
                attributes: parse_nlas(buffer)?,
            },
            NL80211_CMD_GET_STATION => Self {
                cmd: Nl80211Cmd::StationGet,
                attributes: parse_nlas(buffer)?,
            },
            NL80211_CMD_NEW_STATION => Self {
                cmd: Nl80211Cmd::StationNew,
                attributes: parse_nlas(buffer)?,
            },
            NL80211_CMD_NEW_WIPHY => Self {
                cmd: Nl80211Cmd::WiphyNew,
                attributes: parse_nlas(buffer)?,
            },
            NL80211_CMD_NEW_SCAN_RESULTS => Self {
                cmd: Nl80211Cmd::ScanGet,
                attributes: parse_nlas(buffer)?,
            },
            cmd => {
                return Err(DecodeError::from(format!(
                    "Unsupported nl80211 reply command: {}",
                    cmd
                )))
            }
        })
    }
}
