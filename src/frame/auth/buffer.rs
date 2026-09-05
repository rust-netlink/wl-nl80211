// SPDX-License-Identifier: MIT

use std::mem::size_of;

use netlink_packet_core::DecodeError;
use zerocopy::{
    byteorder::little_endian::U16, FromBytes, Immutable, IntoBytes,
    KnownLayout, Unaligned,
};

use crate::Ieee80211StatusCode;

/// Frame Control type/subtype mask (802.11-2020 §9.2.4.1.3, bits 2-7).
pub(crate) const FRAME_CTRL_TYPE_SUBTYPE_MASK: u16 = 0x00FC;
/// Frame Control type/subtype of a management Authentication frame
/// (type 0, subtype 11).
pub(crate) const FRAME_CTRL_MGMT_AUTH: u16 = 0x00B0;

/// Fixed 30 bytes of a management Authentication frame: 24-byte MAC header
/// plus the Authentication algorithm, transaction sequence number and status
/// code fields.
pub(crate) const AUTH_FRAME_FIXED_LEN: usize =
    size_of::<Ieee80211AuthFrameBuffer>();

/// Raw little-endian wire layout of the fixed part of an Authentication
/// frame. The remaining body is variable length and is kept separately.
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
pub(crate) struct Ieee80211AuthFrameBuffer {
    frame_control: U16,
    duration: U16,
    da: [u8; 6],
    sa: [u8; 6],
    bssid: [u8; 6],
    seq_ctrl: U16,
    auth_alg: U16,
    transaction: U16,
    status_code: U16,
}

/// Decoded fixed fields shared by every 802.11 Authentication frame.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) struct Ieee80211AuthFrameFixed {
    pub(crate) frame_control: u16,
    pub(crate) duration: u16,
    pub(crate) da: [u8; 6],
    pub(crate) sa: [u8; 6],
    pub(crate) bssid: [u8; 6],
    pub(crate) seq_ctrl: u16,
    pub(crate) auth_alg: u16,
    pub(crate) transaction: u16,
    pub(crate) status_code: Ieee80211StatusCode,
}

/// Parse and validate the fixed part of an 802.11 Authentication frame.
///
/// When `expected_alg` is `Some`, the Authentication Algorithm Number must
/// match it exactly.
pub(crate) fn parse_auth_frame(
    data: &[u8],
    expected_alg: Option<u16>,
) -> Result<(Ieee80211AuthFrameFixed, &[u8]), DecodeError> {
    let (raw, payload) = Ieee80211AuthFrameBuffer::ref_from_prefix(data)
        .map_err(|_| {
            DecodeError::buffer_too_small(data.len(), AUTH_FRAME_FIXED_LEN)
        })?;

    let frame_control = raw.frame_control.get();
    if frame_control & FRAME_CTRL_TYPE_SUBTYPE_MASK != FRAME_CTRL_MGMT_AUTH {
        return Err(DecodeError::from(format!(
            "not a management Authentication frame: frame control \
             {frame_control:#06x}"
        )));
    }

    let auth_alg = raw.auth_alg.get();
    if let Some(expected_alg) = expected_alg {
        if auth_alg != expected_alg {
            return Err(DecodeError::from(format!(
                "unexpected Authentication algorithm {auth_alg}, expected \
                 {expected_alg}"
            )));
        }
    }

    Ok((
        Ieee80211AuthFrameFixed {
            frame_control,
            duration: raw.duration.get(),
            da: raw.da,
            sa: raw.sa,
            bssid: raw.bssid,
            seq_ctrl: raw.seq_ctrl.get(),
            auth_alg,
            transaction: raw.transaction.get(),
            status_code: Ieee80211StatusCode::from(raw.status_code.get()),
        },
        payload,
    ))
}

/// Total buffer length of an Authentication frame with `payload_len` bytes
/// of body data.
pub(crate) fn auth_frame_buffer_len(payload_len: usize) -> usize {
    AUTH_FRAME_FIXED_LEN + payload_len
}

/// Emit the fixed part plus `payload` into `buffer`.
pub(crate) fn emit_auth_frame(
    fixed: &Ieee80211AuthFrameFixed,
    payload: &[u8],
    buffer: &mut [u8],
) {
    let raw = Ieee80211AuthFrameBuffer::from(fixed);
    buffer[..AUTH_FRAME_FIXED_LEN].copy_from_slice(raw.as_bytes());
    buffer[AUTH_FRAME_FIXED_LEN..].copy_from_slice(payload);
}

impl From<&Ieee80211AuthFrameFixed> for Ieee80211AuthFrameBuffer {
    fn from(fixed: &Ieee80211AuthFrameFixed) -> Self {
        Self {
            frame_control: U16::new(fixed.frame_control),
            duration: U16::new(fixed.duration),
            da: fixed.da,
            sa: fixed.sa,
            bssid: fixed.bssid,
            seq_ctrl: U16::new(fixed.seq_ctrl),
            auth_alg: U16::new(fixed.auth_alg),
            transaction: U16::new(fixed.transaction),
            status_code: U16::new(u16::from(fixed.status_code)),
        }
    }
}
