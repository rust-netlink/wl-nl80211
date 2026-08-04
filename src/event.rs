// SPDX-License-Identifier: MIT

use genetlink::message::RawGenlMessage;
use netlink_packet_core::{NetlinkMessage, NetlinkPayload};

use crate::event_status::{Nl80211EventCode, Nl80211EventReason};
use crate::{Nl80211Attr, Nl80211AuthFrame, Nl80211Command, Nl80211Message};

/// A multicast nl80211 event received from the kernel, e.g. on the `mlme`,
/// `scan` or `config` groups (see [`crate::new_multicast_connection`]).
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum Nl80211Event {
    /// `NL80211_CMD_AUTHENTICATE` event: the authentication result. `status`
    /// is [`Nl80211EventCode`]; `frame` is the full 802.11 authentication
    /// frame when the kernel delivered one (SAE exchanges).
    Authenticated {
        status: Nl80211EventCode,
        frame: Option<Vec<u8>>,
    },
    /// `NL80211_CMD_ASSOCIATE` event: the association result. `ies` are the
    /// information elements from the Association Response frame (they carry
    /// e.g. the AP's OWE DH Parameter Element for OWE networks).
    Associated {
        status: Nl80211EventCode,
        ies: Option<Vec<u8>>,
    },
    /// `NL80211_CMD_CONNECT` event: the connection result.
    ConnectResult { status: Nl80211EventCode },
    /// `NL80211_CMD_DISCONNECT` event: the IEEE 802.11 reason code.
    Disconnect { reason: Nl80211EventReason },
    /// `NL80211_CMD_FRAME` event: a received management frame the socket
    /// registered for.
    Frame { frame: Vec<u8> },
    /// `NL80211_CMD_CONTROL_PORT_FRAME` event: an EAPOL (802.1X control
    /// port) frame received over nl80211.
    ControlPortFrame { frame: Vec<u8> },
    /// `NL80211_CMD_PORT_AUTHORIZED` event: the driver authorized the
    /// control port for the peer.
    PortAuthorized,
    /// `NL80211_CMD_TRIGGER_SCAN` event: a scan started.
    ScanStart,
    /// `NL80211_CMD_NEW_SCAN_RESULTS` event: a scan finished and new BSS
    /// results are available (retrieve them via a scan dump).
    NewScanResults,
    /// `NL80211_CMD_EXTERNAL_AUTH` event: the kernel asks userspace to
    /// perform the authentication (e.g. SAE) externally.
    ExternalAuth,
    /// Any other command: carries the unmodelled [`Nl80211Command`].
    Unknown { cmd: Nl80211Command },
}

impl Nl80211Event {
    /// Parse a raw netlink message received from the nl80211 multicast
    /// groups into a typed event.
    ///
    /// The `NetlinkMessage<RawGenlMessage>` values come from the
    /// `UnboundedReceiver` returned by [`crate::new_multicast_connection`].
    /// Returns `None` when the message is a netlink error or cannot be
    /// parsed as an nl80211 message.
    pub fn parse(msg: NetlinkMessage<RawGenlMessage>) -> Option<Nl80211Event> {
        let (_header, payload) = msg.into_parts();
        match payload {
            NetlinkPayload::InnerMessage(raw_genlmsg) => {
                match raw_genlmsg.parse_into_genlmsg::<Nl80211Message>() {
                    Ok(genl_msg) => {
                        let nl_msg = genl_msg.payload;
                        match nl_msg.cmd {
                            Nl80211Command::ExternalAuth => {
                                Some(Nl80211Event::ExternalAuth)
                            }
                            Nl80211Command::Connect => {
                                Some(Nl80211Event::ConnectResult {
                                    status: attr_status(&nl_msg).into(),
                                })
                            }
                            Nl80211Command::Disconnect => {
                                Some(Nl80211Event::Disconnect {
                                    reason: attr_reason(&nl_msg).into(),
                                })
                            }
                            Nl80211Command::Frame => attr_frame(&nl_msg)
                                .map(|frame| Nl80211Event::Frame { frame }),
                            Nl80211Command::PortAuthorized => {
                                Some(Nl80211Event::PortAuthorized)
                            }
                            Nl80211Command::TriggerScan => {
                                Some(Nl80211Event::ScanStart)
                            }
                            Nl80211Command::NewScanResults => {
                                Some(Nl80211Event::NewScanResults)
                            }
                            Nl80211Command::Authenticate => {
                                Some(parse_authenticate(&nl_msg))
                            }
                            Nl80211Command::Associate => {
                                Some(parse_associate(&nl_msg))
                            }
                            Nl80211Command::ControlPortFrame => {
                                attr_frame(&nl_msg).map(|frame| {
                                    Nl80211Event::ControlPortFrame { frame }
                                })
                            }
                            other => Some(Nl80211Event::Unknown { cmd: other }),
                        }
                    }
                    Err(e) => {
                        log::warn!("Failed to parse nl80211 event: {e}");
                        None
                    }
                }
            }
            NetlinkPayload::Error(err) => {
                log::warn!("Netlink error event: {err:?}");
                None
            }
            _ => None,
        }
    }
}

fn attr_status(msg: &Nl80211Message) -> u16 {
    msg.attributes
        .iter()
        .find_map(|attr| match attr {
            Nl80211Attr::StatusCode(code) => Some(*code),
            _ => None,
        })
        .unwrap_or(0)
}

fn attr_reason(msg: &Nl80211Message) -> u16 {
    msg.attributes
        .iter()
        .find_map(|attr| match attr {
            Nl80211Attr::ReasonCode(code) => Some(*code),
            _ => None,
        })
        .unwrap_or(0)
}

fn attr_frame(msg: &Nl80211Message) -> Option<Vec<u8>> {
    msg.attributes.iter().find_map(|attr| match attr {
        Nl80211Attr::Frame(frame) => Some(frame.clone()),
        _ => None,
    })
}

fn attr_ie(msg: &Nl80211Message) -> Option<Vec<u8>> {
    msg.attributes.iter().find_map(|attr| match attr {
        Nl80211Attr::Ie(ie) => Some(ie.clone()),
        _ => None,
    })
}

fn parse_authenticate(msg: &Nl80211Message) -> Nl80211Event {
    let mut status = Nl80211EventCode::from(attr_status(msg));
    let frame = attr_frame(msg);

    // The kernel may deliver the authentication result without a
    // NL80211_ATTR_STATUS_CODE, relying on the status code inside the
    // 802.11 authentication frame.
    if status == Nl80211EventCode::Success {
        if let Some(ref frame) = frame {
            if let Ok(auth_frame) = Nl80211AuthFrame::parse(frame) {
                status = auth_frame.status;
            }
        }
    }

    Nl80211Event::Authenticated { status, frame }
}

fn parse_associate(msg: &Nl80211Message) -> Nl80211Event {
    let status = attr_status(msg);
    let mut ies = attr_ie(msg);

    // When the kernel omits NL80211_ATTR_IE, the IEs are inside the full
    // association response frame, starting after the 24-byte 802.11 header +
    // capability(2) + status(2) + AID(2) = offset 30.
    if ies.is_none() {
        if let Some(frame) = attr_frame(msg) {
            if frame.len() > 30 {
                ies = Some(frame[30..].to_vec());
            }
        }
    }

    Nl80211Event::Associated {
        status: status.into(),
        ies,
    }
}
