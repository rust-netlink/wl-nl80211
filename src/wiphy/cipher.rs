// SPDX-License-Identifier: MIT

const WLAN_CIPHER_SUITE_USE_GROUP: u32 = 0x000FAC << 8;
const WLAN_CIPHER_SUITE_WEP40: u32 = 0x000FAC << 8 | 1;
const WLAN_CIPHER_SUITE_TKIP: u32 = 0x000FAC << 8 | 2;
const WLAN_CIPHER_SUITE_CCMP: u32 = 0x000FAC << 8 | 4;
const WLAN_CIPHER_SUITE_WEP104: u32 = 0x000FAC << 8 | 5;
const WLAN_CIPHER_SUITE_AES_CMAC: u32 = 0x000FAC << 8 | 6;
const WLAN_CIPHER_SUITE_GCMP: u32 = 0x000FAC << 8 | 8;
const WLAN_CIPHER_SUITE_GCMP_256: u32 = 0x000FAC << 8 | 9;
const WLAN_CIPHER_SUITE_CCMP_256: u32 = 0x000FAC << 8 | 10;
const WLAN_CIPHER_SUITE_BIP_GMAC_128: u32 = 0x000FAC << 8 | 11;
const WLAN_CIPHER_SUITE_BIP_GMAC_256: u32 = 0x000FAC << 8 | 12;
const WLAN_CIPHER_SUITE_BIP_CMAC_256: u32 = 0x000FAC << 8 | 13;
const WLAN_CIPHER_SUITE_SMS4: u32 = 0x001472 << 8 | 1;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Nl80211CipherSuit {
    UseGroup,
    Wep40,
    Tkip,
    Ccmp,
    Wep104,
    AesCmac,
    Gcmp,
    Gcmp256,
    Ccmp256,
    BipGmac128,
    BipGmac256,
    BipCmac256,
    Sms4,
    Other(u32),
}

impl From<u32> for Nl80211CipherSuit {
    fn from(d: u32) -> Self {
        match d {
            WLAN_CIPHER_SUITE_USE_GROUP => Self::UseGroup,
            WLAN_CIPHER_SUITE_WEP40 => Self::Wep40,
            WLAN_CIPHER_SUITE_TKIP => Self::Tkip,
            WLAN_CIPHER_SUITE_CCMP => Self::Ccmp,
            WLAN_CIPHER_SUITE_WEP104 => Self::Wep104,
            WLAN_CIPHER_SUITE_AES_CMAC => Self::AesCmac,
            WLAN_CIPHER_SUITE_GCMP => Self::Gcmp,
            WLAN_CIPHER_SUITE_GCMP_256 => Self::Gcmp256,
            WLAN_CIPHER_SUITE_CCMP_256 => Self::Ccmp256,
            WLAN_CIPHER_SUITE_BIP_GMAC_128 => Self::BipGmac128,
            WLAN_CIPHER_SUITE_BIP_GMAC_256 => Self::BipGmac256,
            WLAN_CIPHER_SUITE_BIP_CMAC_256 => Self::BipCmac256,
            WLAN_CIPHER_SUITE_SMS4 => Self::Sms4,
            _ => Self::Other(d),
        }
    }
}

impl From<Nl80211CipherSuit> for u32 {
    fn from(v: Nl80211CipherSuit) -> u32 {
        match v {
            Nl80211CipherSuit::UseGroup => WLAN_CIPHER_SUITE_USE_GROUP,
            Nl80211CipherSuit::Wep40 => WLAN_CIPHER_SUITE_WEP40,
            Nl80211CipherSuit::Tkip => WLAN_CIPHER_SUITE_TKIP,
            Nl80211CipherSuit::Ccmp => WLAN_CIPHER_SUITE_CCMP,
            Nl80211CipherSuit::Wep104 => WLAN_CIPHER_SUITE_WEP104,
            Nl80211CipherSuit::AesCmac => WLAN_CIPHER_SUITE_AES_CMAC,
            Nl80211CipherSuit::Gcmp => WLAN_CIPHER_SUITE_GCMP,
            Nl80211CipherSuit::Gcmp256 => WLAN_CIPHER_SUITE_GCMP_256,
            Nl80211CipherSuit::Ccmp256 => WLAN_CIPHER_SUITE_CCMP_256,
            Nl80211CipherSuit::BipGmac128 => WLAN_CIPHER_SUITE_BIP_GMAC_128,
            Nl80211CipherSuit::BipGmac256 => WLAN_CIPHER_SUITE_BIP_GMAC_256,
            Nl80211CipherSuit::BipCmac256 => WLAN_CIPHER_SUITE_BIP_CMAC_256,
            Nl80211CipherSuit::Sms4 => WLAN_CIPHER_SUITE_SMS4,
            Nl80211CipherSuit::Other(d) => d,
        }
    }
}
