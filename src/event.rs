// SPDX-License-Identifier: MIT

use genetlink::message::RawGenlMessage;
use netlink_packet_core::{NetlinkMessage, NetlinkPayload};

use crate::event_status::{Ieee80211ReasonCode, Ieee80211StatusCode};
use crate::{
    Ieee80211AssocRespFrame, Ieee80211AuthFrame, Ieee80211EapolFrame,
    Ieee80211Frame, Nl80211Attr, Nl80211Command, Nl80211CqmRssiEvent,
    Nl80211Message, Nl80211WowlanTriggersSupport, Nl80211WowlanWakeup,
};

/// `NL80211_CMD_AUTHENTICATE` event.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct Nl80211EventAuthenticated {
    /// The authentication result status.
    pub status: Ieee80211StatusCode,
    /// The full 802.11 authentication frame, parsed, when the kernel
    /// delivered one (SAE exchanges).
    pub frame: Option<Ieee80211AuthFrame>,
}

/// `NL80211_CMD_ASSOCIATE` event.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct Nl80211EventAssociated {
    /// The association result status.
    pub status: Ieee80211StatusCode,
    /// Information elements from the Association Response frame.
    pub ies: Option<Vec<u8>>,
}

/// A multicast nl80211 event received from the kernel, e.g. on the `mlme`,
/// `scan` or `config` groups (see [`crate::new_multicast_connection`]).
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum Nl80211Event {
    /// `NL80211_CMD_AUTHENTICATE` event: the authentication result.
    Authenticated(Nl80211EventAuthenticated),
    /// `NL80211_CMD_ASSOCIATE` event: the association result.
    Associated(Nl80211EventAssociated),
    /// `NL80211_CMD_CONNECT` event: the connection result.
    ConnectResult(Ieee80211StatusCode),
    /// `NL80211_CMD_DISCONNECT` event.
    Disconnect(Ieee80211ReasonCode),
    /// `NL80211_CMD_DEAUTHENTICATE` event.
    Deauthenticated(Ieee80211ReasonCode),
    /// `NL80211_CMD_DISASSOCIATE` event.
    Disassociated(Ieee80211ReasonCode),
    /// `NL80211_CMD_FRAME` event: a received management frame.
    Frame(Ieee80211Frame),
    /// `NL80211_CMD_CONTROL_PORT_FRAME` event.
    ControlPortFrame(Ieee80211EapolFrame),
    /// `NL80211_CMD_PORT_AUTHORIZED` event.
    PortAuthorized,
    /// `NL80211_CMD_TRIGGER_SCAN` event.
    ScanStart,
    /// `NL80211_CMD_NEW_SCAN_RESULTS` event.
    NewScanResults,
    /// `NL80211_CMD_EXTERNAL_AUTH` event.
    ExternalAuth,
    /// `NL80211_CMD_SET_WOWLAN` wake notification.
    WowlanWakeup(Vec<Nl80211WowlanWakeup>),
    /// `NL80211_CMD_NOTIFY_CQM` event.
    CqmRssi(Nl80211CqmRssiEvent),
    /// Any other command.
    Unknown(Nl80211Command),
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
                                Some(Nl80211Event::ConnectResult(attr_status(
                                    &nl_msg,
                                )))
                            }
                            Nl80211Command::Disconnect => {
                                Some(Nl80211Event::Disconnect(
                                    attr_reason(&nl_msg).into(),
                                ))
                            }
                            Nl80211Command::Deauthenticate => {
                                attr_frame_reason(&nl_msg)
                                    .map(Nl80211Event::Deauthenticated)
                                    .or(Some(Nl80211Event::Unknown(
                                        Nl80211Command::Deauthenticate,
                                    )))
                            }
                            Nl80211Command::Disassociate => {
                                attr_frame_reason(&nl_msg)
                                    .map(Nl80211Event::Disassociated)
                                    .or(Some(Nl80211Event::Unknown(
                                        Nl80211Command::Disassociate,
                                    )))
                            }
                            Nl80211Command::Frame => attr_frame(&nl_msg)
                                .and_then(|frame| {
                                    Ieee80211Frame::parse(&frame).ok()
                                })
                                .map(Nl80211Event::Frame),
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
                                    Nl80211Event::ControlPortFrame(
                                        Ieee80211EapolFrame::parse(&frame),
                                    )
                                })
                            }
                            Nl80211Command::NotifyCqm => {
                                Some(parse_cqm(&nl_msg))
                            }
                            // The kernel also uses SET_WOWLAN as a wakeup
                            // notification; without the wakeup attribute
                            // (e.g. echoing our own trigger config) it
                            // stays an unmodelled event.
                            Nl80211Command::SetWowlan => {
                                attr_wowlan_wakeup(&nl_msg)
                                    .map(Nl80211Event::WowlanWakeup)
                                    .or(Some(Nl80211Event::Unknown(
                                        Nl80211Command::SetWowlan,
                                    )))
                            }
                            other => Some(Nl80211Event::Unknown(other)),
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

fn attr_status(msg: &Nl80211Message) -> Ieee80211StatusCode {
    msg.attributes
        .iter()
        .find_map(|attr| match attr {
            Nl80211Attr::StatusCode(code) => Some(*code),
            _ => None,
        })
        .unwrap_or(Ieee80211StatusCode::Success)
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

/// The IEEE 802.11 reason code of a deauth/disassoc event. The kernel
/// reports these events with the full management frame in
/// `NL80211_ATTR_FRAME` and no `NL80211_ATTR_REASON_CODE`; the reason
/// code sits at offset 24-25 of the frame (after the 24-byte 802.11
/// header).
fn attr_frame_reason(msg: &Nl80211Message) -> Option<Ieee80211ReasonCode> {
    msg.attributes.iter().find_map(|attr| match attr {
        Nl80211Attr::Frame(frame) if frame.len() >= 26 => {
            Some(Ieee80211ReasonCode::from(u16::from_le_bytes([
                frame[24], frame[25],
            ])))
        }
        _ => None,
    })
}

fn attr_frame(msg: &Nl80211Message) -> Option<Vec<u8>> {
    msg.attributes.iter().find_map(|attr| match attr {
        Nl80211Attr::Frame(frame) => Some(frame.clone()),
        _ => None,
    })
}

fn attr_wowlan_wakeup(
    msg: &Nl80211Message,
) -> Option<Vec<Nl80211WowlanWakeup>> {
    msg.attributes.iter().find_map(|attr| match attr {
        Nl80211Attr::WowlanTriggers(triggers) => Some(
            triggers
                .iter()
                .filter_map(wowlan_wakeup_from_support)
                .collect(),
        ),
        _ => None,
    })
}

/// Convert an armed trigger (as parsed from `NL80211_ATTR_WOWLAN_TRIGGERS`)
/// into the wake reason it represents. Flag triggers map directly;
/// set/capability-side payload triggers (`PktPattern`, `NetDetect`,
/// `TcpConnection`) have no wake-report equivalent and are skipped.
fn wowlan_wakeup_from_support(
    trigger: &Nl80211WowlanTriggersSupport,
) -> Option<Nl80211WowlanWakeup> {
    match trigger {
        Nl80211WowlanTriggersSupport::Any => Some(Nl80211WowlanWakeup::Any),
        Nl80211WowlanTriggersSupport::Disconnect => {
            Some(Nl80211WowlanWakeup::Disconnect)
        }
        Nl80211WowlanTriggersSupport::MagicPkt => {
            Some(Nl80211WowlanWakeup::MagicPkt)
        }
        Nl80211WowlanTriggersSupport::GtkRekeyFailure => {
            Some(Nl80211WowlanWakeup::GtkRekeyFailure)
        }
        Nl80211WowlanTriggersSupport::EapIdentRequest => {
            Some(Nl80211WowlanWakeup::EapIdentRequest)
        }
        Nl80211WowlanTriggersSupport::FourWayHandshake => {
            Some(Nl80211WowlanWakeup::FourWayHandshake)
        }
        Nl80211WowlanTriggersSupport::RfkillRelease => {
            Some(Nl80211WowlanWakeup::RfkillRelease)
        }
        Nl80211WowlanTriggersSupport::Other(nla) => {
            Some(Nl80211WowlanWakeup::Other(nla.clone()))
        }
        Nl80211WowlanTriggersSupport::PktPattern(_)
        | Nl80211WowlanTriggersSupport::GtkRekeySupported
        | Nl80211WowlanTriggersSupport::NetDetect(_)
        | Nl80211WowlanTriggersSupport::TcpConnection(_) => None,
    }
}

fn attr_ie(msg: &Nl80211Message) -> Option<Vec<u8>> {
    msg.attributes.iter().find_map(|attr| match attr {
        Nl80211Attr::Ie(ie) => Some(ie.clone()),
        _ => None,
    })
}

fn parse_cqm(msg: &Nl80211Message) -> Nl80211Event {
    let mut wiphy = 0;
    let mut if_index = 0;
    let mut mac = None;
    let mut events = Vec::new();
    for attr in &msg.attributes {
        match attr {
            Nl80211Attr::Wiphy(w) => wiphy = *w,
            Nl80211Attr::IfIndex(i) => if_index = *i,
            Nl80211Attr::Mac(m) => mac = Some(*m),
            Nl80211Attr::Cqm(cqm) => events.extend(cqm.iter().cloned()),
            _ => {}
        }
    }
    Nl80211Event::CqmRssi(Nl80211CqmRssiEvent {
        wiphy,
        if_index,
        mac,
        events,
    })
}

fn parse_authenticate(msg: &Nl80211Message) -> Nl80211Event {
    let mut status = attr_status(msg);
    let frame = attr_frame(msg)
        .and_then(|frame| Ieee80211AuthFrame::parse(&frame).ok());

    // The kernel may deliver the authentication result without a
    // NL80211_ATTR_STATUS_CODE, relying on the status code inside the
    // 802.11 authentication frame.
    if status == Ieee80211StatusCode::Success {
        if let Some(ref frame) = frame {
            status = frame.status_code();
        }
    }

    Nl80211Event::Authenticated(Nl80211EventAuthenticated { status, frame })
}

fn parse_associate(msg: &Nl80211Message) -> Nl80211Event {
    // mac80211/cfg80211 deliver the (Re)Association Response as a full
    // management frame in NL80211_ATTR_FRAME, without
    // NL80211_ATTR_STATUS_CODE. Parse the standard frame layout for the
    // status code and the response IEs.
    let assoc_frame = attr_frame(msg)
        .and_then(|frame| Ieee80211AssocRespFrame::parse(&frame).ok());

    let status = assoc_frame
        .as_ref()
        .map(|frame| frame.status_code)
        .or_else(|| {
            msg.attributes.iter().find_map(|attr| match attr {
                Nl80211Attr::StatusCode(code) => Some(*code),
                _ => None,
            })
        })
        .unwrap_or(Ieee80211StatusCode::Success);
    // The parsed frame body keeps AID(2) + IEs as `remains`; the event's
    // IEs start after the AID.
    let ies = attr_ie(msg).or_else(|| {
        assoc_frame
            .as_ref()
            .map(|frame| frame.remains.get(2..).unwrap_or_default().to_vec())
    });

    Nl80211Event::Associated(Nl80211EventAssociated { status, ies })
}
