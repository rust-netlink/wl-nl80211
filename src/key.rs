// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    emit_u32, parse_u32, parse_u8, DecodeError, DefaultNla, ErrorContext, Nla,
    NlaBuffer, Parseable,
};

const NL80211_KEYTYPE_GROUP: u32 = 0;
const NL80211_KEYTYPE_PAIRWISE: u32 = 1;
const NL80211_KEYTYPE_PMK: u32 = 2;

/// Key type, used as the `NL80211_KEY_TYPE` sub-attribute.
///
/// Mirrors the kernel `enum nl80211_key_type`.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
#[non_exhaustive]
pub enum Nl80211KeyType {
    /// Group (broadcast/multicast) key.
    #[default]
    Group,
    /// Pairwise (unicast) key.
    Pairwise,
    /// PMK (used for offloaded authentication).
    Pmk,
    /// Any other / kernel-version-specific value.
    Other(u32),
}

impl From<u32> for Nl80211KeyType {
    fn from(d: u32) -> Self {
        match d {
            NL80211_KEYTYPE_GROUP => Self::Group,
            NL80211_KEYTYPE_PAIRWISE => Self::Pairwise,
            NL80211_KEYTYPE_PMK => Self::Pmk,
            _ => Self::Other(d),
        }
    }
}

impl From<Nl80211KeyType> for u32 {
    fn from(v: Nl80211KeyType) -> u32 {
        match v {
            Nl80211KeyType::Group => NL80211_KEYTYPE_GROUP,
            Nl80211KeyType::Pairwise => NL80211_KEYTYPE_PAIRWISE,
            Nl80211KeyType::Pmk => NL80211_KEYTYPE_PMK,
            Nl80211KeyType::Other(d) => d,
        }
    }
}

const NL80211_KEY_DATA: u16 = 1;
const NL80211_KEY_IDX: u16 = 2;
const NL80211_KEY_CIPHER: u16 = 3;
const NL80211_KEY_SEQ: u16 = 4;
const NL80211_KEY_DEFAULT: u16 = 5;
const NL80211_KEY_DEFAULT_MGMT: u16 = 6;
const NL80211_KEY_TYPE: u16 = 7;
const NL80211_KEY_MODE: u16 = 9;

/// Key sub-attribute within the nested `NL80211_ATTR_KEY` attribute, used to
/// install a key with `NL80211_CMD_NEW_KEY` / `NL80211_CMD_SET_KEY`.
///
/// Mirrors the kernel `enum nl80211_key_attributes`.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum Nl80211KeyAttr {
    /// Key material (e.g. the 16-byte CCMP temporal key).
    Data(Vec<u8>),
    /// Key index (0 for the pairwise key, 1-3 for group keys, etc.).
    Idx(u8),
    /// Cipher suite selector in the kernel-native encoding (e.g. `0x000FAC04`
    /// for CCMP-128).
    Cipher(u32),
    /// Receive sequence counter / packet number (RSC) for the key.
    Seq(Vec<u8>),
    /// Flag marking the key as the default (TX) key.
    Default,
    /// Flag marking the key as the default management-frame (BIP) key.
    DefaultMgmt,
    /// Key type (pairwise/group/PMK).
    Type(Nl80211KeyType),
    /// Key mode (see kernel `enum nl80211_key_mode`).
    Mode(u8),
    /// Any other / kernel-version-specific sub-attribute.
    Other(DefaultNla),
}

impl Nla for Nl80211KeyAttr {
    fn value_len(&self) -> usize {
        match self {
            Self::Data(v) | Self::Seq(v) => v.len(),
            Self::Idx(_) | Self::Mode(_) => 1,
            Self::Cipher(_) | Self::Type(_) => 4,
            Self::Default | Self::DefaultMgmt => 0,
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Data(_) => NL80211_KEY_DATA,
            Self::Idx(_) => NL80211_KEY_IDX,
            Self::Cipher(_) => NL80211_KEY_CIPHER,
            Self::Seq(_) => NL80211_KEY_SEQ,
            Self::Default => NL80211_KEY_DEFAULT,
            Self::DefaultMgmt => NL80211_KEY_DEFAULT_MGMT,
            Self::Type(_) => NL80211_KEY_TYPE,
            Self::Mode(_) => NL80211_KEY_MODE,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Data(v) | Self::Seq(v) => {
                buffer[..v.len()].copy_from_slice(v)
            }
            Self::Idx(d) | Self::Mode(d) => buffer[0] = *d,
            Self::Cipher(d) => emit_u32(buffer, *d).unwrap(),
            Self::Type(d) => emit_u32(buffer, u32::from(*d)).unwrap(),
            Self::Default | Self::DefaultMgmt => (),
            Self::Other(attr) => attr.emit_value(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for Nl80211KeyAttr
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NL80211_KEY_DATA => Self::Data(payload.to_vec()),
            NL80211_KEY_SEQ => Self::Seq(payload.to_vec()),
            NL80211_KEY_IDX => {
                let err_msg = format!("Invalid NL80211_KEY_IDX {payload:?}");
                Self::Idx(parse_u8(payload).context(err_msg)?)
            }
            NL80211_KEY_MODE => {
                let err_msg = format!("Invalid NL80211_KEY_MODE {payload:?}");
                Self::Mode(parse_u8(payload).context(err_msg)?)
            }
            NL80211_KEY_CIPHER => {
                let err_msg = format!("Invalid NL80211_KEY_CIPHER {payload:?}");
                Self::Cipher(parse_u32(payload).context(err_msg)?)
            }
            NL80211_KEY_TYPE => {
                let err_msg = format!("Invalid NL80211_KEY_TYPE {payload:?}");
                Self::Type(parse_u32(payload).context(err_msg)?.into())
            }
            NL80211_KEY_DEFAULT => Self::Default,
            NL80211_KEY_DEFAULT_MGMT => Self::DefaultMgmt,
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}
