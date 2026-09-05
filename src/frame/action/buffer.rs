// SPDX-License-Identifier: MIT

use std::mem::size_of;

use netlink_packet_core::DecodeError;
use zerocopy::{
    byteorder::little_endian::U16, FromBytes, Immutable, IntoBytes,
    KnownLayout, Unaligned,
};

/// Frame Control type/subtype mask (802.11-2020 §9.2.4.1.3, bits 2-7).
pub(crate) const FRAME_CTRL_TYPE_SUBTYPE_MASK: u16 = 0x00FC;
/// Frame Control type/subtype of a management Action frame.
pub(crate) const FRAME_CTRL_MGMT_ACTION: u16 = 0x00D0;
/// Fixed 26 bytes of a management Action frame: 24-byte MAC header plus the
/// category and action octets.
pub(crate) const ACTION_FRAME_FIXED_LEN: usize =
    size_of::<Ieee80211ActionFrameBuffer>();

/// Raw little-endian wire layout of the fixed part of an Action frame. The
/// remaining Action body is variable length and is kept separately.
#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
)]
#[repr(C, packed)]
struct Ieee80211ActionFrameBuffer {
    frame_control: U16,
    duration: U16,
    da: [u8; 6],
    sa: [u8; 6],
    bssid: [u8; 6],
    seq_ctrl: U16,
    category: u8,
    action: u8,
}

/// Decoded fixed fields shared by every IEEE 802.11 Action frame.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) struct Ieee80211ActionFrameFixed {
    pub(crate) frame_control: u16,
    pub(crate) duration: u16,
    pub(crate) da: [u8; 6],
    pub(crate) sa: [u8; 6],
    pub(crate) bssid: [u8; 6],
    pub(crate) seq_ctrl: u16,
    pub(crate) category: u8,
    pub(crate) action: u8,
}

/// Parse and validate the fixed part of an IEEE 802.11 Action frame.
pub(crate) fn parse_action_frame(
    data: &[u8],
) -> Result<(Ieee80211ActionFrameFixed, &[u8]), DecodeError> {
    let (raw, body) = Ieee80211ActionFrameBuffer::ref_from_prefix(data)
        .map_err(|_| {
            DecodeError::buffer_too_small(data.len(), ACTION_FRAME_FIXED_LEN)
        })?;

    let frame_control = raw.frame_control.get();
    if frame_control & FRAME_CTRL_TYPE_SUBTYPE_MASK != FRAME_CTRL_MGMT_ACTION {
        return Err(DecodeError::from(format!(
            "not a management Action frame: frame control \
             {frame_control:#06x}"
        )));
    }

    Ok((
        Ieee80211ActionFrameFixed {
            frame_control,
            duration: raw.duration.get(),
            da: raw.da,
            sa: raw.sa,
            bssid: raw.bssid,
            seq_ctrl: raw.seq_ctrl.get(),
            category: raw.category,
            action: raw.action,
        },
        body,
    ))
}

/// Total buffer length of an Action frame with `body_len` bytes of body
/// data after the category and action octets.
pub(crate) fn action_frame_buffer_len(body_len: usize) -> usize {
    ACTION_FRAME_FIXED_LEN + body_len
}

/// Emit the fixed part plus `body` into `buffer`.
pub(crate) fn emit_action_frame(
    fixed: &Ieee80211ActionFrameFixed,
    body: &[u8],
    buffer: &mut [u8],
) {
    let raw = Ieee80211ActionFrameBuffer::from(fixed);
    buffer[..ACTION_FRAME_FIXED_LEN].copy_from_slice(raw.as_bytes());
    buffer[ACTION_FRAME_FIXED_LEN..].copy_from_slice(body);
}

impl From<&Ieee80211ActionFrameFixed> for Ieee80211ActionFrameBuffer {
    fn from(fixed: &Ieee80211ActionFrameFixed) -> Self {
        Self {
            frame_control: U16::new(fixed.frame_control),
            duration: U16::new(fixed.duration),
            da: fixed.da,
            sa: fixed.sa,
            bssid: fixed.bssid,
            seq_ctrl: U16::new(fixed.seq_ctrl),
            category: fixed.category,
            action: fixed.action,
        }
    }
}
