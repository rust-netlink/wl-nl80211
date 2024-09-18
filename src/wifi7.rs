// SPDX-License-Identifier: MIT

// WIFI 7(802.11be) specific data types

use netlink_packet_utils::{DecodeError, Emitable};

const EHT_MAC_CAP_INFO_LEN: usize = 2;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Nl80211EhtMacCapInfo(pub [u8; EHT_MAC_CAP_INFO_LEN]);

// TODO: Failed to get WIFI7(802.11be) SPEC PDF, hence no parsing functions
impl Nl80211EhtMacCapInfo {
    pub const LENGTH: usize = EHT_MAC_CAP_INFO_LEN;

    pub fn new(value: &[u8]) -> Self {
        let mut data = [0u8; Self::LENGTH];
        if value.len() > Self::LENGTH {
            data.copy_from_slice(&value[..Self::LENGTH]);
        } else {
            data[..value.len()].copy_from_slice(value)
        }
        Self(data)
    }
}

impl Emitable for Nl80211EhtMacCapInfo {
    fn buffer_len(&self) -> usize {
        EHT_MAC_CAP_INFO_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        if buffer.len() < EHT_MAC_CAP_INFO_LEN {
            log::error!(
                "Buffer size is smaller than EHT_MAC_CAP_INFO_LEN \
                {EHT_MAC_CAP_INFO_LEN}"
            );
            return;
        }
        buffer[..EHT_MAC_CAP_INFO_LEN].copy_from_slice(&self.0)
    }
}

const EHT_PHY_CAP_INFO_LEN: usize = 9;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Nl80211EhtPhyCapInfo(pub [u8; EHT_PHY_CAP_INFO_LEN]);

impl Nl80211EhtPhyCapInfo {
    pub const LENGTH: usize = EHT_PHY_CAP_INFO_LEN;

    pub fn new(value: &[u8]) -> Self {
        let mut data = [0u8; Self::LENGTH];
        if value.len() > Self::LENGTH {
            data.copy_from_slice(&value[..Self::LENGTH]);
        } else {
            data[..value.len()].copy_from_slice(value)
        }
        Self(data)
    }
}

impl Emitable for Nl80211EhtPhyCapInfo {
    fn buffer_len(&self) -> usize {
        Self::LENGTH
    }

    fn emit(&self, buffer: &mut [u8]) {
        if buffer.len() < EHT_PHY_CAP_INFO_LEN {
            log::error!(
                "Buffer size is smaller than EHT_PHY_CAP_INFO_LEN \
                {EHT_PHY_CAP_INFO_LEN}"
            );
            return;
        }
        buffer[..EHT_PHY_CAP_INFO_LEN].copy_from_slice(&self.0)
    }
}

/// MCS/NSS support for 20 MHz-only STA.
// Kernel data type: `struct ieee80211_eht_mcs_nss_supp_20mhz_only`
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Nl80211EhtMcsNssSuppOnly20Mhz {
    /// MCS 0 - 7
    pub rx_tx_mcs7_max_nss: u8,
    /// MCS 8 - 9
    pub rx_tx_mcs9_max_nss: u8,
    /// MCS 10 - 11
    pub rx_tx_mcs11_max_nss: u8,
    /// MCS 12 - 13
    pub rx_tx_mcs13_max_nss: u8,
}

impl Nl80211EhtMcsNssSuppOnly20Mhz {
    pub const LENGTH: usize = 4;

    pub fn parse(buf: &[u8]) -> Self {
        Self {
            rx_tx_mcs7_max_nss: *buf.first().unwrap_or(&0),
            rx_tx_mcs9_max_nss: *buf.get(1).unwrap_or(&0),
            rx_tx_mcs11_max_nss: *buf.get(2).unwrap_or(&0),
            rx_tx_mcs13_max_nss: *buf.get(3).unwrap_or(&0),
        }
    }
}

impl Emitable for Nl80211EhtMcsNssSuppOnly20Mhz {
    fn buffer_len(&self) -> usize {
        Self::LENGTH
    }

    fn emit(&self, buffer: &mut [u8]) {
        if buffer.len() < Self::LENGTH {
            log::error!(
                "Buffer size is smaller than required length {}",
                Self::LENGTH
            );
            return;
        }
        buffer[0] = self.rx_tx_mcs7_max_nss;
        buffer[1] = self.rx_tx_mcs9_max_nss;
        buffer[2] = self.rx_tx_mcs11_max_nss;
        buffer[3] = self.rx_tx_mcs13_max_nss;
    }
}

// Kernel data type: `struct ieee80211_eht_mcs_nss_supp_bw`
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Nl80211EhtMcsNssSuppBw {
    /// MCS 8 - 9
    pub rx_tx_mcs9_max_nss: u8,
    /// MCS 10 - 11
    pub rx_tx_mcs11_max_nss: u8,
    /// MCS 12 - 13
    pub rx_tx_mcs13_max_nss: u8,
}

impl Nl80211EhtMcsNssSuppBw {
    pub const LENGTH: usize = 3;

    pub fn parse(buf: &[u8]) -> Self {
        Self {
            rx_tx_mcs9_max_nss: *buf.first().unwrap_or(&0),
            rx_tx_mcs11_max_nss: *buf.get(1).unwrap_or(&0),
            rx_tx_mcs13_max_nss: *buf.get(2).unwrap_or(&0),
        }
    }
}

impl Emitable for Nl80211EhtMcsNssSuppBw {
    fn buffer_len(&self) -> usize {
        Self::LENGTH
    }

    fn emit(&self, buffer: &mut [u8]) {
        if buffer.len() < Self::LENGTH {
            log::error!(
                "Buffer size is smaller than required length {}",
                Self::LENGTH
            );
            return;
        }
        buffer[0] = self.rx_tx_mcs9_max_nss;
        buffer[1] = self.rx_tx_mcs11_max_nss;
        buffer[2] = self.rx_tx_mcs13_max_nss;
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Nl80211EhtMcsNssSuppMoreThan20Mhz {
    pub mhz_80: Nl80211EhtMcsNssSuppBw,
    pub mhz_160: Nl80211EhtMcsNssSuppBw,
    pub mhz_320: Nl80211EhtMcsNssSuppBw,
}

impl Nl80211EhtMcsNssSuppMoreThan20Mhz {
    pub const LENGTH: usize = Nl80211EhtMcsNssSuppBw::LENGTH * 3;

    pub fn parse(buf: &[u8]) -> Self {
        Self {
            mhz_80: Nl80211EhtMcsNssSuppBw::parse(buf),
            mhz_160: Nl80211EhtMcsNssSuppBw::parse(
                &buf[Nl80211EhtMcsNssSuppMoreThan20Mhz::LENGTH..],
            ),
            mhz_320: Nl80211EhtMcsNssSuppBw::parse(
                &buf[Nl80211EhtMcsNssSuppMoreThan20Mhz::LENGTH * 2..],
            ),
        }
    }
}

impl Emitable for Nl80211EhtMcsNssSuppMoreThan20Mhz {
    fn buffer_len(&self) -> usize {
        Self::LENGTH
    }

    fn emit(&self, buffer: &mut [u8]) {
        if buffer.len() < Self::LENGTH {
            log::error!(
                "Buffer size is smaller than required length {}",
                Self::LENGTH
            );
            return;
        }
        self.mhz_80.emit(buffer);
        self.mhz_160
            .emit(&mut buffer[Nl80211EhtMcsNssSuppMoreThan20Mhz::LENGTH..]);
        self.mhz_320
            .emit(&mut buffer[Nl80211EhtMcsNssSuppMoreThan20Mhz::LENGTH * 2..]);
    }
}

// Kernel data type: `struct ieee80211_eht_mcs_nss_supp`
///  EHT max supported NSS per MCS
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Nl80211EhtMcsNssSupp {
    Only20Mhz(Nl80211EhtMcsNssSuppOnly20Mhz),
    MoreThan20Mhz(Nl80211EhtMcsNssSuppMoreThan20Mhz),
    /// This other might be removed once 802.11be standard published
    Other(Vec<u8>),
}

impl Emitable for Nl80211EhtMcsNssSupp {
    fn buffer_len(&self) -> usize {
        match self {
            Self::Only20Mhz(_) => Nl80211EhtMcsNssSuppOnly20Mhz::LENGTH,
            Self::MoreThan20Mhz(_) => Nl80211EhtMcsNssSuppMoreThan20Mhz::LENGTH,
            Self::Other(v) => v.len(),
        }
    }

    fn emit(&self, buffer: &mut [u8]) {
        match self {
            Self::Only20Mhz(v) => v.emit(buffer),
            Self::MoreThan20Mhz(v) => v.emit(buffer),
            Self::Other(v) => buffer.copy_from_slice(&v[..buffer.len()]),
        }
    }
}

impl Nl80211EhtMcsNssSupp {
    pub fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        if buf.len() > Nl80211EhtMcsNssSuppOnly20Mhz::LENGTH {
            if buf.len() >= Nl80211EhtMcsNssSuppMoreThan20Mhz::LENGTH {
                Ok(Self::MoreThan20Mhz(
                    Nl80211EhtMcsNssSuppMoreThan20Mhz::parse(buf),
                ))
            } else {
                Err(format!(
                    "Invalid NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MCS_SET \
                    data, expecting u8 array with size {} or {}, but got {}",
                    Nl80211EhtMcsNssSuppOnly20Mhz::LENGTH,
                    Nl80211EhtMcsNssSuppMoreThan20Mhz::LENGTH,
                    buf.len()
                )
                .into())
            }
        } else {
            Ok(Self::Only20Mhz(Nl80211EhtMcsNssSuppOnly20Mhz::parse(buf)))
        }
    }
}

const IEEE80211_EHT_PPE_THRES_MAX_LEN: usize = 32;

/// PPE thresholds
// TODO: write passing function
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Nl80211EhtPpeThres(pub [u8; IEEE80211_EHT_PPE_THRES_MAX_LEN]);

impl Nl80211EhtPpeThres {
    pub const LENGTH: usize = IEEE80211_EHT_PPE_THRES_MAX_LEN;

    pub fn new(value: &[u8]) -> Self {
        let mut data = [0u8; Self::LENGTH];
        if value.len() > Self::LENGTH {
            data.copy_from_slice(&value[..Self::LENGTH]);
        } else {
            data[..value.len()].copy_from_slice(value)
        }
        Self(data)
    }
}

impl Emitable for Nl80211EhtPpeThres {
    fn buffer_len(&self) -> usize {
        Self::LENGTH
    }

    fn emit(&self, buffer: &mut [u8]) {
        if buffer.len() < Self::LENGTH {
            log::error!(
                "Buffer size is smaller than required length {}",
                Self::LENGTH
            );
            return;
        }
        buffer[..Self::LENGTH].copy_from_slice(&self.0)
    }
}
