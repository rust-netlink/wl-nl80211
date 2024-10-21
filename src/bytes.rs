// SPDX-License-Identifier: MIT

use netlink_packet_utils::DecodeError;

pub(crate) fn write_u16(buffer: &mut [u8], value: u16) {
    buffer[..2].copy_from_slice(&value.to_ne_bytes())
}

pub(crate) fn write_u16_le(buffer: &mut [u8], value: u16) {
    buffer[..2].copy_from_slice(&value.to_le_bytes())
}

pub(crate) fn write_u32(buffer: &mut [u8], value: u32) {
    buffer[..4].copy_from_slice(&value.to_ne_bytes())
}

pub(crate) fn write_u32_le(buffer: &mut [u8], value: u32) {
    buffer[..4].copy_from_slice(&value.to_le_bytes())
}

pub(crate) fn write_i32(buffer: &mut [u8], value: i32) {
    buffer[..4].copy_from_slice(&value.to_ne_bytes())
}

pub(crate) fn write_u64(buffer: &mut [u8], value: u64) {
    buffer[..8].copy_from_slice(&value.to_ne_bytes())
}

/// The `pos` is index from bit 0.
pub(crate) fn get_bit(data: &[u8], pos: usize) -> bool {
    let index: usize = pos / 8;
    let bit_pos: usize = pos % 8;
    if data.len() < index {
        panic!(
            "BUG: get_bit(): out of index: got data {:?} pos {pos}",
            data
        );
    }
    (data[index] & 1u8 << bit_pos) >= 1
}

/// The `start` is index from bit 0.
pub(crate) fn get_bits_as_u8(data: &[u8], start: usize, end: usize) -> u8 {
    if (end - start) >= 8 {
        panic!(
            "BUG: get_bits_as_u8(): more than 8 bits defined by \
            start({start}) and end({end})"
        );
    }

    let mut ret = 0u8;
    for pos in start..(end + 1) {
        if get_bit(data, pos) {
            ret |= 1 << (pos - start);
        }
    }
    ret
}

pub(crate) fn parse_u16_le(payload: &[u8]) -> Result<u16, DecodeError> {
    if payload.len() < 2 {
        return Err(format!("Invalid payload for u16: {:?}", payload).into());
    }
    Ok(u16::from_le_bytes([payload[0], payload[1]]))
}
