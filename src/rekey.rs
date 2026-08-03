// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    emit_u32, parse_u32, DecodeError, DefaultNla, ErrorContext, Nla, NlaBuffer,
    Parseable,
};

const NL80211_REKEY_DATA_KEK: u16 = 1;
const NL80211_REKEY_DATA_KCK: u16 = 2;
const NL80211_REKEY_DATA_REPLAY_CTR: u16 = 3;
const NL80211_REKEY_DATA_AKM: u16 = 4;

/// Sub-attributes within the nested `NL80211_ATTR_REKEY_DATA` attribute,
/// used with `NL80211_CMD_SET_REKEY_OFFLOAD` to hand GTK rekey material
/// to the driver/firmware.
///
/// Mirrors the kernel `enum nl80211_rekey_data`.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum Nl80211RekeyData {
    /// Key Encryption Key (16–32 bytes depending on AKM).
    Kek(Vec<u8>),
    /// Key Confirmation Key (16–24 bytes depending on AKM).
    Kck(Vec<u8>),
    /// Replay counter (8 bytes).
    ReplayCtr(Vec<u8>),
    /// AKM suite selector (kernel-native encoding, e.g. `0x000FAC08`
    /// for SAE).
    Akm(u32),
    /// Any other / kernel-version-specific sub-attribute.
    Other(DefaultNla),
}

impl Nla for Nl80211RekeyData {
    fn value_len(&self) -> usize {
        match self {
            Self::Kek(v) | Self::Kck(v) | Self::ReplayCtr(v) => v.len(),
            Self::Akm(_) => 4,
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Kek(_) => NL80211_REKEY_DATA_KEK,
            Self::Kck(_) => NL80211_REKEY_DATA_KCK,
            Self::ReplayCtr(_) => NL80211_REKEY_DATA_REPLAY_CTR,
            Self::Akm(_) => NL80211_REKEY_DATA_AKM,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Kek(v) | Self::Kck(v) | Self::ReplayCtr(v) => {
                buffer[..v.len()].copy_from_slice(v)
            }
            Self::Akm(d) => emit_u32(buffer, *d).unwrap(),
            Self::Other(attr) => attr.emit_value(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for Nl80211RekeyData
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NL80211_REKEY_DATA_KEK => Self::Kek(payload.to_vec()),
            NL80211_REKEY_DATA_KCK => Self::Kck(payload.to_vec()),
            NL80211_REKEY_DATA_REPLAY_CTR => Self::ReplayCtr(payload.to_vec()),
            NL80211_REKEY_DATA_AKM => {
                let err_msg =
                    format!("Invalid NL80211_REKEY_DATA_AKM {payload:?}");
                Self::Akm(parse_u32(payload).context(err_msg)?)
            }
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}
