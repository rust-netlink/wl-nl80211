// SPDX-License-Identifier: MIT

use futures::TryStream;
use netlink_packet_core::{NLM_F_ACK, NLM_F_REQUEST};
use netlink_packet_generic::GenlMessage;

use crate::{
    nl80211_execute, Nl80211Attr, Nl80211AttrsBuilder, Nl80211Command,
    Nl80211Error, Nl80211Handle, Nl80211Message,
};

/// Helper to build the attribute list for the driver PMKSA cache commands
/// `NL80211_CMD_SET_PMKSA` and `NL80211_CMD_DEL_PMKSA`.
///
/// The kernel requires [`pmkid`](Nl80211AttrsBuilder::<Nl80211Pmksa>::pmkid)
/// and the BSSID via [`mac`](Nl80211AttrsBuilder::<Nl80211Pmksa>::mac);
/// `SET_PMKSA` additionally takes the PMK material and (optionally) the
/// lifetime / reauthentication threshold.
#[derive(Debug)]
pub struct Nl80211Pmksa;

impl Nl80211Pmksa {
    /// Start building a PMKSA cache request for the interface `if_index`.
    pub fn new(if_index: u32) -> Nl80211AttrsBuilder<Self> {
        Nl80211AttrsBuilder::<Self>::new().if_index(if_index)
    }
}

impl Nl80211AttrsBuilder<Nl80211Pmksa> {
    /// The 16-octet PMKID of the cache entry.
    pub fn pmkid(self, pmkid: Vec<u8>) -> Self {
        self.replace(Nl80211Attr::Pmkid(pmkid))
    }

    /// BSSID of the AP the PMKSA cache entry belongs to.
    pub fn mac(self, mac: [u8; 6]) -> Self {
        self.replace(Nl80211Attr::Mac(mac))
    }

    /// The PMK belonging to the cache entry.
    pub fn pmk(self, pmk: Vec<u8>) -> Self {
        self.replace(Nl80211Attr::Pmk(pmk))
    }

    /// Maximum lifetime of the cache entry in seconds
    /// (`NL80211_ATTR_PMK_LIFETIME`).
    pub fn pmk_lifetime(self, seconds: u32) -> Self {
        self.replace(Nl80211Attr::PmkLifetime(seconds))
    }

    /// Reauthentication threshold in percent of the lifetime
    /// (`NL80211_ATTR_PMK_REAUTH_THRESHOLD`).
    pub fn pmk_reauth_threshold(self, percent: u8) -> Self {
        self.replace(Nl80211Attr::PmkReauthThreshold(percent))
    }
}

pub struct Nl80211SetPmksaRequest {
    handle: Nl80211Handle,
    attributes: Vec<Nl80211Attr>,
}

impl Nl80211SetPmksaRequest {
    pub(crate) fn new(
        handle: Nl80211Handle,
        attributes: Vec<Nl80211Attr>,
    ) -> Self {
        Nl80211SetPmksaRequest { handle, attributes }
    }

    /// Send the `NL80211_CMD_SET_PMKSA` request.
    ///
    /// Fails with `-EOPNOTSUPP` when the driver has no `set_pmksa` op
    /// (e.g. mac80211-based drivers without AP-side PMKSA caching).
    pub async fn execute(
        self,
    ) -> impl TryStream<Ok = GenlMessage<Nl80211Message>, Error = Nl80211Error>
    {
        let Nl80211SetPmksaRequest {
            mut handle,
            attributes,
        } = self;
        let nl80211_msg = Nl80211Message {
            cmd: Nl80211Command::SetPmksa,
            attributes,
        };
        nl80211_execute(&mut handle, nl80211_msg, NLM_F_REQUEST | NLM_F_ACK)
            .await
    }
}

pub struct Nl80211DelPmksaRequest {
    handle: Nl80211Handle,
    attributes: Vec<Nl80211Attr>,
}

impl Nl80211DelPmksaRequest {
    pub(crate) fn new(
        handle: Nl80211Handle,
        attributes: Vec<Nl80211Attr>,
    ) -> Self {
        Nl80211DelPmksaRequest { handle, attributes }
    }

    /// Send the `NL80211_CMD_DEL_PMKSA` request.
    pub async fn execute(
        self,
    ) -> impl TryStream<Ok = GenlMessage<Nl80211Message>, Error = Nl80211Error>
    {
        let Nl80211DelPmksaRequest {
            mut handle,
            attributes,
        } = self;
        let nl80211_msg = Nl80211Message {
            cmd: Nl80211Command::DelPmksa,
            attributes,
        };
        nl80211_execute(&mut handle, nl80211_msg, NLM_F_REQUEST | NLM_F_ACK)
            .await
    }
}

pub struct Nl80211FlushPmksaRequest {
    handle: Nl80211Handle,
    attributes: Vec<Nl80211Attr>,
}

impl Nl80211FlushPmksaRequest {
    pub(crate) fn new(
        handle: Nl80211Handle,
        attributes: Vec<Nl80211Attr>,
    ) -> Self {
        Nl80211FlushPmksaRequest { handle, attributes }
    }

    /// Send the `NL80211_CMD_FLUSH_PMKSA` request (drop every driver
    /// PMKSA cache entry of the interface).
    pub async fn execute(
        self,
    ) -> impl TryStream<Ok = GenlMessage<Nl80211Message>, Error = Nl80211Error>
    {
        let Nl80211FlushPmksaRequest {
            mut handle,
            attributes,
        } = self;
        let nl80211_msg = Nl80211Message {
            cmd: Nl80211Command::FlushPmksa,
            attributes,
        };
        nl80211_execute(&mut handle, nl80211_msg, NLM_F_REQUEST | NLM_F_ACK)
            .await
    }
}

/// Helper to build the attribute list for the offloaded-PMK commands
/// `NL80211_CMD_SET_PMK` / `NL80211_CMD_DEL_PMK` (hand the PMK / PMK-R0 to
/// the driver for offloaded 4-way handshake or offloaded Fast BSS
/// Transition).
#[derive(Debug)]
pub struct Nl80211Pmk;

impl Nl80211Pmk {
    /// Start building a PMK request for the interface `if_index`.
    pub fn new(if_index: u32) -> Nl80211AttrsBuilder<Self> {
        Nl80211AttrsBuilder::<Self>::new().if_index(if_index)
    }
}

impl Nl80211AttrsBuilder<Nl80211Pmk> {
    /// The PMK (or PMK-R0) material handed to the driver.
    pub fn pmk(self, pmk: Vec<u8>) -> Self {
        self.replace(Nl80211Attr::Pmk(pmk))
    }
}

pub struct Nl80211SetPmkRequest {
    handle: Nl80211Handle,
    attributes: Vec<Nl80211Attr>,
}

impl Nl80211SetPmkRequest {
    pub(crate) fn new(
        handle: Nl80211Handle,
        attributes: Vec<Nl80211Attr>,
    ) -> Self {
        Nl80211SetPmkRequest { handle, attributes }
    }

    /// Send the `NL80211_CMD_SET_PMK` request.
    pub async fn execute(
        self,
    ) -> impl TryStream<Ok = GenlMessage<Nl80211Message>, Error = Nl80211Error>
    {
        let Nl80211SetPmkRequest {
            mut handle,
            attributes,
        } = self;
        let nl80211_msg = Nl80211Message {
            cmd: Nl80211Command::SetPmk,
            attributes,
        };
        nl80211_execute(&mut handle, nl80211_msg, NLM_F_REQUEST | NLM_F_ACK)
            .await
    }
}

pub struct Nl80211DelPmkRequest {
    handle: Nl80211Handle,
    attributes: Vec<Nl80211Attr>,
}

impl Nl80211DelPmkRequest {
    pub(crate) fn new(
        handle: Nl80211Handle,
        attributes: Vec<Nl80211Attr>,
    ) -> Self {
        Nl80211DelPmkRequest { handle, attributes }
    }

    /// Send the `NL80211_CMD_DEL_PMK` request (clear the PMK previously
    /// set via [`Nl80211SetPmkRequest`]).
    pub async fn execute(
        self,
    ) -> impl TryStream<Ok = GenlMessage<Nl80211Message>, Error = Nl80211Error>
    {
        let Nl80211DelPmkRequest {
            mut handle,
            attributes,
        } = self;
        let nl80211_msg = Nl80211Message {
            cmd: Nl80211Command::DelPmk,
            attributes,
        };
        nl80211_execute(&mut handle, nl80211_msg, NLM_F_REQUEST | NLM_F_ACK)
            .await
    }
}
