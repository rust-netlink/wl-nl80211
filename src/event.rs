// SPDX-License-Identifier: MIT

use genetlink::message::RawGenlMessage;
use netlink_packet_core::{NetlinkMessage, NetlinkPayload};

use crate::event_status::{Nl80211EventCode, Nl80211EventReason};
use crate::{
    Nl80211Attr, Nl80211AuthFrame, Nl80211Command, Nl80211Message,
    Nl80211WowlanTriggersSupport, Nl80211WowlanWakeup,
};

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
    /// `NL80211_CMD_DEAUTHENTICATE` event: the AP deauthenticated the STA;
    /// `reason` is the IEEE 802.11 reason code (e.g. 2
    /// `PrevAuthNotValid` / 23 `Ieee8021xFailed` indicate a fatal
    /// credential problem, anything else is transient).
    Deauthenticated { reason: Nl80211EventReason },
    /// `NL80211_CMD_DISASSOCIATE` event: the AP disassociated the STA;
    /// `reason` is the IEEE 802.11 reason code.
    Disassociated { reason: Nl80211EventReason },
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
    /// `NL80211_CMD_SET_WOWLAN` event: the device woke up while the host
    /// was suspended; `reasons` carries the `NL80211_ATTR_WOWLAN_TRIGGERS`
    /// sub-attributes reported by `cfg80211_report_wowlan_wakeup()`.
    WowlanWakeup { reasons: Vec<Nl80211WowlanWakeup> },
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
                            Nl80211Command::Deauthenticate => {
                                attr_frame_reason(&nl_msg)
                                    .map(|reason| {
                                        Nl80211Event::Deauthenticated { reason }
                                    })
                                    .or(Some(Nl80211Event::Unknown {
                                        cmd: Nl80211Command::Deauthenticate,
                                    }))
                            }
                            Nl80211Command::Disassociate => {
                                attr_frame_reason(&nl_msg)
                                    .map(|reason| Nl80211Event::Disassociated {
                                        reason,
                                    })
                                    .or(Some(Nl80211Event::Unknown {
                                        cmd: Nl80211Command::Disassociate,
                                    }))
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
                            // The kernel also uses SET_WOWLAN as a wakeup
                            // notification; without the wakeup attribute
                            // (e.g. echoing our own trigger config) it
                            // stays an unmodelled event.
                            Nl80211Command::SetWowlan => {
                                attr_wowlan_wakeup(&nl_msg)
                                    .map(|reasons| Nl80211Event::WowlanWakeup {
                                        reasons,
                                    })
                                    .or(Some(Nl80211Event::Unknown {
                                        cmd: Nl80211Command::SetWowlan,
                                    }))
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

/// The IEEE 802.11 reason code of a deauth/disassoc event. The kernel
/// reports these events with the full management frame in
/// `NL80211_ATTR_FRAME` and no `NL80211_ATTR_REASON_CODE`; the reason
/// code sits at offset 24-25 of the frame (after the 24-byte 802.11
/// header).
fn attr_frame_reason(msg: &Nl80211Message) -> Option<Nl80211EventReason> {
    msg.attributes.iter().find_map(|attr| match attr {
        Nl80211Attr::Frame(frame) if frame.len() >= 26 => {
            Some(Nl80211EventReason::from(u16::from_le_bytes([
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
