// SPDX-License-Identifier: MIT

use crate::{
    Nl80211AssociateRequest, Nl80211Attr, Nl80211AuthenticateRequest,
    Nl80211ConnectRequest, Nl80211ControlPortFrameRequest,
    Nl80211DelPmkRequest, Nl80211DelPmksaRequest, Nl80211DisconnectRequest,
    Nl80211ExternalAuthRequest, Nl80211FlushPmksaRequest, Nl80211FrameRequest,
    Nl80211Handle, Nl80211KeyRequest, Nl80211RegisterFrameRequest,
    Nl80211RekeyOffloadRequest, Nl80211SetPmkRequest, Nl80211SetPmksaRequest,
    Nl80211WowlanRequest,
};

/// A handle to send connection management commands (`NL80211_CMD_CONNECT` and
/// `NL80211_CMD_DISCONNECT`) for a station (managed) interface.
#[derive(Debug, Clone)]
pub struct Nl80211ConnectionHandle(Nl80211Handle);

impl Nl80211ConnectionHandle {
    pub fn new(handle: Nl80211Handle) -> Self {
        Nl80211ConnectionHandle(handle)
    }

    /// Request a connection (equivalent to `iw dev DEVICE connect`).
    ///
    /// The `attributes` are normally produced by [`crate::Nl80211Connect`],
    /// for example:
    ///
    /// ```no_run
    /// use wl_nl80211::Nl80211Connect;
    ///
    /// let if_index = 0u32;
    /// let attrs = Nl80211Connect::new(if_index)
    ///     .ssid("Test-WIFI")
    ///     .wpa3_personal()
    ///     .build();
    /// # let _ = attrs;
    /// ```
    pub fn connect(
        &mut self,
        attributes: Vec<Nl80211Attr>,
    ) -> Nl80211ConnectRequest {
        Nl80211ConnectRequest::new(self.0.clone(), attributes)
    }

    /// Request a disconnection (equivalent to `iw dev DEVICE disconnect`).
    ///
    /// The `attributes` are normally produced by [`crate::Nl80211Disconnect`].
    pub fn disconnect(
        &mut self,
        attributes: Vec<Nl80211Attr>,
    ) -> Nl80211DisconnectRequest {
        Nl80211DisconnectRequest::new(self.0.clone(), attributes)
    }

    /// Authenticate to an AP (`NL80211_CMD_AUTHENTICATE`), the
    /// SME-in-userspace path. For SAE the commit / confirm bodies are carried
    /// in the `attributes`, normally produced by
    /// [`crate::Nl80211Authenticate`].
    pub fn authenticate(
        &mut self,
        attributes: Vec<Nl80211Attr>,
    ) -> Nl80211AuthenticateRequest {
        Nl80211AuthenticateRequest::new(self.0.clone(), attributes)
    }

    /// Associate to an AP (`NL80211_CMD_ASSOCIATE`), typically right after a
    /// successful [`Self::authenticate`] exchange.
    ///
    /// The `attributes` are normally produced by [`crate::Nl80211Associate`].
    pub fn associate(
        &mut self,
        attributes: Vec<Nl80211Attr>,
    ) -> Nl80211AssociateRequest {
        Nl80211AssociateRequest::new(self.0.clone(), attributes)
    }

    /// Report the result of an externally performed authentication
    /// (`NL80211_CMD_EXTERNAL_AUTH`), e.g. the outcome of a userspace SAE
    /// exchange.
    ///
    /// The `attributes` are normally produced by
    /// [`crate::Nl80211ExternalAuth`].
    pub fn external_auth(
        &mut self,
        attributes: Vec<Nl80211Attr>,
    ) -> Nl80211ExternalAuthRequest {
        Nl80211ExternalAuthRequest::new(self.0.clone(), attributes)
    }

    /// Transmit a management frame (`NL80211_CMD_FRAME`), e.g. an SAE
    /// Authentication frame.
    ///
    /// The `attributes` are normally produced by [`crate::Nl80211Frame`].
    pub fn frame(
        &mut self,
        attributes: Vec<Nl80211Attr>,
    ) -> Nl80211FrameRequest {
        Nl80211FrameRequest::new(self.0.clone(), attributes)
    }

    /// Register the calling socket to receive management frames of a given
    /// type (`NL80211_CMD_REGISTER_FRAME`).
    ///
    /// The `attributes` are normally produced by
    /// [`crate::Nl80211RegisterFrame`]. Note that frames are delivered on the
    /// socket backing this handle, which must stay open to receive them.
    pub fn register_frame(
        &mut self,
        attributes: Vec<Nl80211Attr>,
    ) -> Nl80211RegisterFrameRequest {
        Nl80211RegisterFrameRequest::new(self.0.clone(), attributes)
    }

    /// Transmit an EAPOL control port frame (`NL80211_CMD_CONTROL_PORT_FRAME`).
    ///
    /// The `attributes` are normally produced by
    /// [`crate::Nl80211ControlPortFrame`].
    pub fn control_port_frame(
        &mut self,
        attributes: Vec<Nl80211Attr>,
    ) -> Nl80211ControlPortFrameRequest {
        Nl80211ControlPortFrameRequest::new(self.0.clone(), attributes)
    }

    /// Install a key (`NL80211_CMD_NEW_KEY`), used during the 4-way
    /// handshake to install the PTK / GTK.
    ///
    /// The `attributes` are normally produced by
    /// [`crate::Nl80211Key`], e.g. [`crate::Nl80211Key::new_ptk`] or
    /// [`crate::Nl80211Key::new_gtk`].
    pub fn new_key(
        &mut self,
        attributes: Vec<Nl80211Attr>,
    ) -> Nl80211KeyRequest {
        Nl80211KeyRequest::new(self.0.clone(), attributes)
    }

    /// Hand GTK rekey material to the driver/firmware
    /// (`NL80211_CMD_SET_REKEY_OFFLOAD`), so the device can keep receiving
    /// while the host is suspended (WoWLAN).
    ///
    /// The `attributes` are normally produced by
    /// [`crate::Nl80211RekeyOffload`].
    pub fn set_rekey_offload(
        &mut self,
        attributes: Vec<Nl80211Attr>,
    ) -> Nl80211RekeyOffloadRequest {
        Nl80211RekeyOffloadRequest::new(self.0.clone(), attributes)
    }

    /// Arm WoWLAN triggers (`NL80211_CMD_SET_WOWLAN`), so the device can
    /// wake the host while it is suspended (e.g. on a GTK rekey failure).
    ///
    /// The `attributes` are normally produced by
    /// [`crate::Nl80211Wowlan`]. Fails with `-EOPNOTSUPP` on drivers
    /// without WoWLAN support (e.g. mac80211_hwsim).
    pub fn set_wowlan(
        &mut self,
        attributes: Vec<Nl80211Attr>,
    ) -> Nl80211WowlanRequest {
        Nl80211WowlanRequest::new(self.0.clone(), attributes)
    }

    /// Add a PMKSA cache entry to the driver/firmware
    /// (`NL80211_CMD_SET_PMKSA`), so the driver can skip full
    /// authentication on reconnects / roaming.
    ///
    /// The `attributes` are normally produced by [`crate::Nl80211Pmksa`].
    /// Fails with `-EOPNOTSUPP` on drivers without a `set_pmksa` op.
    pub fn set_pmksa(
        &mut self,
        attributes: Vec<Nl80211Attr>,
    ) -> Nl80211SetPmksaRequest {
        Nl80211SetPmksaRequest::new(self.0.clone(), attributes)
    }

    /// Delete a driver/firmware PMKSA cache entry
    /// (`NL80211_CMD_DEL_PMKSA`).
    ///
    /// The `attributes` are normally produced by [`crate::Nl80211Pmksa`].
    pub fn del_pmksa(
        &mut self,
        attributes: Vec<Nl80211Attr>,
    ) -> Nl80211DelPmksaRequest {
        Nl80211DelPmksaRequest::new(self.0.clone(), attributes)
    }

    /// Delete every driver/firmware PMKSA cache entry of the interface
    /// (`NL80211_CMD_FLUSH_PMKSA`).
    pub fn flush_pmksa(
        &mut self,
        attributes: Vec<Nl80211Attr>,
    ) -> Nl80211FlushPmksaRequest {
        Nl80211FlushPmksaRequest::new(self.0.clone(), attributes)
    }

    /// Hand the PMK (or PMK-R0) to the driver for offloaded key
    /// management (`NL80211_CMD_SET_PMK`).
    ///
    /// The `attributes` are normally produced by [`crate::Nl80211Pmk`].
    pub fn set_pmk(
        &mut self,
        attributes: Vec<Nl80211Attr>,
    ) -> Nl80211SetPmkRequest {
        Nl80211SetPmkRequest::new(self.0.clone(), attributes)
    }

    /// Clear the PMK previously handed to the driver via
    /// [`Self::set_pmk`] (`NL80211_CMD_DEL_PMK`).
    pub fn del_pmk(
        &mut self,
        attributes: Vec<Nl80211Attr>,
    ) -> Nl80211DelPmkRequest {
        Nl80211DelPmkRequest::new(self.0.clone(), attributes)
    }
}
