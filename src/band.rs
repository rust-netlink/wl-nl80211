// SPDX-License-Identifier: MIT

//! Channel / operating-class helpers used to turn neighbor-report
//! entries (802.11k / BTM candidate lists) into frequencies for quick
//! roaming scans.
//!
//! The `Channel Number` field of a Neighbor Report element is the
//! *primary* channel of the AP, so the center-frequency formulas of
//! Annex E apply regardless of the BSS channel width.

/// A global IEEE 802.11 operating class (802.11-2020 Annex E, Table E-1).
///
/// Local (country-specific) operating classes are mapped to [`Other`]; they
/// are rejected by [`channel_to_freq`].
///
/// [`Other`]: Ieee80211OperatingClass::Other
/// [`channel_to_freq`]: Ieee80211OperatingClass::channel_to_freq
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Ieee80211OperatingClass {
    /// Global operating classes 81-87 (2.4 GHz, 20/40 MHz channels 1-14).
    Global2_4GHz(u8),
    /// Global operating classes 115-130 (5 GHz, channels 32-196).
    Global5GHz(u8),
    /// Global operating classes 131-155 (6 GHz, channel numbers 1, 5, ...,
    /// 233).
    Global6GHz(u8),
    /// Any other operating class number.
    Other(u8),
}

impl Ieee80211OperatingClass {
    /// Map the primary channel number of this operating class to its
    /// frequency in MHz. Returns `None` for classes and channels without a
    /// global Annex E mapping.
    pub fn channel_to_freq(self, channel: u8) -> Option<u32> {
        match self {
            Self::Global2_4GHz(operating_class) => {
                match (operating_class, channel) {
                    (_, 1..=13) => Some(2407 + u32::from(channel) * 5),
                    (82, 14) => Some(2484),
                    _ => None,
                }
            }
            Self::Global5GHz(_) if (32..=196).contains(&channel) => {
                Some(5000 + u32::from(channel) * 5)
            }
            Self::Global6GHz(_) if channel % 2 == 1 && channel <= 233 => {
                Some(5950 + u32::from(channel) * 5)
            }
            Self::Global5GHz(_) | Self::Global6GHz(_) | Self::Other(_) => None,
        }
    }
}

impl From<u8> for Ieee80211OperatingClass {
    fn from(operating_class: u8) -> Self {
        match operating_class {
            81..=87 => Self::Global2_4GHz(operating_class),
            115..=130 => Self::Global5GHz(operating_class),
            131..=155 => Self::Global6GHz(operating_class),
            _ => Self::Other(operating_class),
        }
    }
}
