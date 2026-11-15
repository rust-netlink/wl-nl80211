// SPDX-License-Identifier: MIT

use std::fmt::{self, Display};

use genetlink::GenetlinkError;
use netlink_packet_core::DecodeError;
use netlink_packet_core::{ErrorMessage, NetlinkMessage};
use netlink_packet_generic::GenlMessage;

use crate::Nl80211Message;

#[derive(Debug)]
pub enum Nl80211Error {
    UnexpectedMessage(NetlinkMessage<GenlMessage<Nl80211Message>>),
    NetlinkError(ErrorMessage),
    RequestFailed(String),
    DecodeFailed(DecodeError),
    Bug(String),
}

impl Display for Nl80211Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedMessage(msg) => {
                write!(f, "Received an unexpected message {msg:?}")
            }
            Self::NetlinkError(msg) => {
                write!(f, "Received a netlink error message {msg}")
            }
            Self::RequestFailed(_) => write!(f, "A netlink request failed"),
            Self::DecodeFailed(e) => {
                write!(f, "Failed to decode netlink package: {e}")
            }
            Self::Bug(_) => write!(f, "A bug in this crate"),
        }
    }
}

impl std::error::Error for Nl80211Error {}
impl From<GenetlinkError> for Nl80211Error {
    fn from(err: GenetlinkError) -> Self {
        match err {
            GenetlinkError::NetlinkError(err) => Self::NetlinkError(err),
            GenetlinkError::DecodeError(err) => Self::DecodeFailed(err),
            err => Self::RequestFailed(err.to_string()),
        }
    }
}
