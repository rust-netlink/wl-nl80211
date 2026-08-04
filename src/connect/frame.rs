// SPDX-License-Identifier: MIT

use futures::TryStream;
use netlink_packet_core::{EthernetProtocol, Nla, NLM_F_ACK, NLM_F_REQUEST};
use netlink_packet_generic::GenlMessage;

use crate::{
    nl80211_execute, Nl80211Attr, Nl80211AttrsBuilder, Nl80211Command,
    Nl80211Error, Nl80211Handle, Nl80211Message,
};

/// Helper to build the attribute list for a `NL80211_CMD_FRAME` request, used
/// to transmit a management frame (e.g. an SAE Authentication frame during
/// external authentication).
///
/// The kernel requires the raw
/// [`frame`](Nl80211AttrsBuilder::<Nl80211Frame>::frame) and, unless
/// transmitting on the current operating channel, the
/// [`frequency`](Nl80211AttrsBuilder::<Nl80211Frame>::frequency).
#[derive(Debug)]
pub struct Nl80211Frame;

impl Nl80211Frame {
    /// Start building a frame transmit request for the interface `if_index`.
    pub fn new(if_index: u32) -> Nl80211AttrsBuilder<Self> {
        Nl80211AttrsBuilder::<Self>::new().if_index(if_index)
    }
}

impl Nl80211AttrsBuilder<Nl80211Frame> {
    /// Channel frequency in MHz to transmit the frame on.
    pub fn frequency(self, freq_mhz: u32) -> Self {
        self.replace(Nl80211Attr::WiphyFreq(freq_mhz))
    }

    /// The raw IEEE 802.11 management frame to transmit.
    pub fn frame(self, frame: Vec<u8>) -> Self {
        self.replace(Nl80211Attr::Frame(frame))
    }
}

pub struct Nl80211FrameRequest {
    handle: Nl80211Handle,
    attributes: Vec<Nl80211Attr>,
}

impl Nl80211FrameRequest {
    pub(crate) fn new(
        handle: Nl80211Handle,
        attributes: Vec<Nl80211Attr>,
    ) -> Self {
        Nl80211FrameRequest { handle, attributes }
    }

    /// Send the `NL80211_CMD_FRAME` request.
    ///
    /// On success the kernel replies with a message carrying the
    /// `NL80211_ATTR_COOKIE` identifying the transmitted frame, which can be
    /// matched against the later `NL80211_CMD_FRAME_TX_STATUS` event.
    pub async fn execute(
        self,
    ) -> impl TryStream<Ok = GenlMessage<Nl80211Message>, Error = Nl80211Error>
    {
        let Nl80211FrameRequest {
            mut handle,
            attributes,
        } = self;

        let nl80211_msg = Nl80211Message {
            cmd: Nl80211Command::Frame,
            attributes,
        };
        let flags = NLM_F_REQUEST | NLM_F_ACK;

        nl80211_execute(&mut handle, nl80211_msg, flags).await
    }
}

/// Helper to build the attribute list for a `NL80211_CMD_REGISTER_FRAME`
/// request, used to register the calling socket to receive management frames
/// of a given type (e.g. Authentication frames during external SAE).
///
/// Registration is per-socket: the frames are delivered on the same socket
/// that sent the registration, which must therefore stay open.
#[derive(Debug)]
pub struct Nl80211RegisterFrame;

impl Nl80211RegisterFrame {
    /// Start building a frame registration for the interface `if_index`.
    ///
    /// Defaults the match prefix to empty (match all frames of the registered
    /// type); the kernel requires the match attribute to be present.
    pub fn new(if_index: u32) -> Nl80211AttrsBuilder<Self> {
        Nl80211AttrsBuilder::<Self>::new()
            .if_index(if_index)
            .frame_match(Vec::new())
    }
}

impl Nl80211AttrsBuilder<Nl80211RegisterFrame> {
    /// IEEE 802.11 frame control type/subtype field to register for (e.g.
    /// `0x00b0` for a Management/Authentication frame).
    pub fn frame_type(self, frame_type: u16) -> Self {
        self.replace(Nl80211Attr::FrameType(frame_type))
    }

    /// Byte prefix that received frames must match. An empty match registers
    /// for all frames of the given type.
    pub fn frame_match(self, prefix: Vec<u8>) -> Self {
        self.replace(Nl80211Attr::FrameMatch(prefix))
    }
}

pub struct Nl80211RegisterFrameRequest {
    handle: Nl80211Handle,
    attributes: Vec<Nl80211Attr>,
}

impl Nl80211RegisterFrameRequest {
    pub(crate) fn new(
        handle: Nl80211Handle,
        attributes: Vec<Nl80211Attr>,
    ) -> Self {
        Nl80211RegisterFrameRequest { handle, attributes }
    }

    /// Send the `NL80211_CMD_REGISTER_FRAME` request.
    pub async fn execute(
        self,
    ) -> impl TryStream<Ok = GenlMessage<Nl80211Message>, Error = Nl80211Error>
    {
        let Nl80211RegisterFrameRequest {
            mut handle,
            attributes,
        } = self;

        let nl80211_msg = Nl80211Message {
            cmd: Nl80211Command::RegisterFrame,
            attributes,
        };
        let flags = NLM_F_REQUEST | NLM_F_ACK;

        nl80211_execute(&mut handle, nl80211_msg, flags).await
    }
}

/// Helper to build the attribute list for a `NL80211_CMD_CONTROL_PORT_FRAME`
/// request, transmitting an EAPOL (802.1X control port) frame — e.g. the
/// 4-way handshake messages when the control port is carried over nl80211
/// (`NL80211_ATTR_CONTROL_PORT_OVER_NL80211`, wpa_supplicant's default).
#[derive(Debug)]
pub struct Nl80211ControlPortFrame;

impl Nl80211ControlPortFrame {
    /// Start building a control port frame transmit request for `if_index`.
    pub fn new(if_index: u32) -> Nl80211AttrsBuilder<Self> {
        Nl80211AttrsBuilder::<Self>::new().if_index(if_index)
    }
}

impl Nl80211AttrsBuilder<Nl80211ControlPortFrame> {
    /// BSSID of the AP the EAPOL frame is destined to.
    pub fn mac(self, mac: [u8; 6]) -> Self {
        self.replace(Nl80211Attr::Mac(mac))
    }

    /// The raw EAPOL frame, starting with the EAPOL header.
    pub fn frame(self, frame: Vec<u8>) -> Self {
        self.replace(Nl80211Attr::Frame(frame))
    }

    /// EtherType of the control port frames, e.g.
    /// [`EthernetProtocol::Pae`] (`ETH_P_PAE`, 0x888E) for EAPOL.
    pub fn control_port_ethertype(self, ethertype: EthernetProtocol) -> Self {
        self.replace(Nl80211Attr::ControlPortEthertype(u16::from(ethertype)))
    }

    /// Whether the frames should be transmitted unencrypted
    /// (`NL80211_ATTR_CONTROL_PORT_NO_ENCRYPT`), e.g. for EAPOL frames that
    /// carry their own encryption.
    pub fn control_port_no_encrypt(self, enable: bool) -> Self {
        if enable {
            self.replace(Nl80211Attr::ControlPortNoEncrypt)
        } else {
            self.remove(Nl80211Attr::ControlPortNoEncrypt.kind())
        }
    }
}

pub struct Nl80211ControlPortFrameRequest {
    handle: Nl80211Handle,
    attributes: Vec<Nl80211Attr>,
}

impl Nl80211ControlPortFrameRequest {
    pub(crate) fn new(
        handle: Nl80211Handle,
        attributes: Vec<Nl80211Attr>,
    ) -> Self {
        Nl80211ControlPortFrameRequest { handle, attributes }
    }

    /// Send the `NL80211_CMD_CONTROL_PORT_FRAME` request.
    ///
    /// A successful return only means the kernel accepted the frame for
    /// transmission; the peer's response arrives as a
    /// `NL80211_CMD_CONTROL_PORT_FRAME` event.
    pub async fn execute(
        self,
    ) -> impl TryStream<Ok = GenlMessage<Nl80211Message>, Error = Nl80211Error>
    {
        let Nl80211ControlPortFrameRequest {
            mut handle,
            attributes,
        } = self;

        let nl80211_msg = Nl80211Message {
            cmd: Nl80211Command::ControlPortFrame,
            attributes,
        };
        let flags = NLM_F_REQUEST | NLM_F_ACK;

        nl80211_execute(&mut handle, nl80211_msg, flags).await
    }
}
