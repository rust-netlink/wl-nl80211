// SPDX-License-Identifier: MIT

use anyhow::Context;

use netlink_packet_utils::{
    nla::{Nla, NlasIterator},
    parsers::parse_u32,
    DecodeError,
};

use crate::{bytes::write_u32, Nl80211Command};

pub(crate) struct Nl80211CommandNla {
    index: u16,
    cmd: Nl80211Command,
}

impl Nla for Nl80211CommandNla {
    fn value_len(&self) -> usize {
        4
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        write_u32(buffer, u8::from(self.cmd) as u32)
    }

    fn kind(&self) -> u16 {
        self.index
    }
}

// NL80211_ATTR_SUPPORTED_COMMANDS is using index as NLA kind.
pub(crate) struct Nl80211Commands(Vec<Nl80211CommandNla>);

impl std::ops::Deref for Nl80211Commands {
    type Target = Vec<Nl80211CommandNla>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<&Vec<Nl80211Command>> for Nl80211Commands {
    fn from(cmds: &Vec<Nl80211Command>) -> Self {
        let mut nlas = Vec::new();
        for (i, cmd) in cmds.iter().enumerate() {
            let nla = Nl80211CommandNla {
                index: i as u16,
                cmd: *cmd,
            };
            nlas.push(nla);
        }
        Nl80211Commands(nlas)
    }
}

impl From<Nl80211Commands> for Vec<Nl80211Command> {
    fn from(cmds: Nl80211Commands) -> Self {
        let mut cmds = cmds;
        cmds.0.drain(..).map(|c| c.cmd).collect()
    }
}

impl Nl80211Commands {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let mut cmds: Vec<Nl80211CommandNla> = Vec::new();
        for (index, nla) in NlasIterator::new(payload).enumerate() {
            let error_msg =
                format!("Invalid NL80211_ATTR_SUPPORTED_COMMANDS: {nla:?}");
            let nla = &nla.context(error_msg.clone())?;
            let cmd = Nl80211Command::from(parse_u32(nla.value()).context(
                format!("Invalid NL80211_ATTR_SUPPORTED_COMMANDS: {nla:?}"),
            )? as u8);
            cmds.push(Nl80211CommandNla {
                index: index as u16,
                cmd,
            });
        }
        Ok(Self(cmds))
    }
}
