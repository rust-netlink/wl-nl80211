// SPDX-License-Identifier: MIT

use thiserror::Error;

use netlink_packet_core::{ErrorMessage, NetlinkMessage};
use netlink_packet_generic::GenlMessage;
use netlink_packet_utils::DecodeError;

use crate::Nl80211Message;

#[derive(Debug, Error)]
pub enum Nl80211Error {
    #[error("Received an unexpected message {0:?}")]
    UnexpectedMessage(NetlinkMessage<GenlMessage<Nl80211Message>>),

    #[error("Received a netlink error message {0}")]
    NetlinkError(ErrorMessage),

    #[error("A netlink request failed")]
    RequestFailed(String),

    #[error("Failed to decode netlink package: {0}")]
    DecodeFailed(DecodeError),

    #[error("A bug in this crate")]
    Bug(String),
}
