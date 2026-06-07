// SPDX-License-Identifier: MIT

use crate::{
    Nl80211Attr, Nl80211ConnectRequest, Nl80211DisconnectRequest,
    Nl80211ExternalAuthRequest, Nl80211FrameRequest, Nl80211Handle,
    Nl80211RegisterFrameRequest,
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
}
