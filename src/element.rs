// SPDX-License-Identifier: MIT

use anyhow::Context;
use netlink_packet_utils::{
    parsers::{parse_string, parse_u8},
    DecodeError, Emitable, Parseable,
};

use crate::{
    bytes::{parse_u16_le, write_u16_le, write_u32_le},
    Nl80211ElementHtCap,
};

pub(crate) struct Nl80211Elements(Vec<Nl80211Element>);

impl<T: AsRef<[u8]> + ?Sized> Parseable<T> for Nl80211Elements {
    fn parse(buf: &T) -> Result<Self, DecodeError> {
        let buf = buf.as_ref();
        let mut offset = 0;
        let mut ret = Vec::new();
        while offset < buf.len() && offset + 1 < buf.len() {
            let length = buf[offset + 1] as usize + 2;
            if buf.len() < offset + length {
                break;
            }
            let element = Nl80211Element::parse(&buf[offset..offset + length])?;
            offset += length;
            ret.push(element);
        }
        Ok(Self(ret))
    }
}

impl Emitable for Nl80211Elements {
    fn buffer_len(&self) -> usize {
        self.0.as_slice().iter().map(|e| e.buffer_len()).sum()
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut offset = 0;
        for element in self.0.as_slice().iter() {
            element.emit(&mut buffer[offset..(offset + element.buffer_len())]);
            offset += element.buffer_len();
        }
    }
}

impl From<&Vec<Nl80211Element>> for Nl80211Elements {
    fn from(d: &Vec<Nl80211Element>) -> Self {
        Self(d.to_vec())
    }
}

impl From<Nl80211Elements> for Vec<Nl80211Element> {
    fn from(v: Nl80211Elements) -> Vec<Nl80211Element> {
        v.0
    }
}

// These are `Element IDs` defined in IEEE 802.11-2020
const ELEMENT_ID_SSID: u8 = 0;
const ELEMENT_ID_SUPPORTED_RATES: u8 = 1;
const ELEMENT_ID_CHANNEL: u8 = 3;
const ELEMENT_ID_COUNTRY: u8 = 7;
const ELEMENT_ID_HT_CAP: u8 = 45;
const ELEMENT_ID_RSN: u8 = 48;
const ELEMENT_ID_VENDOR: u8 = 221;

/// IEEE 802.11-2020 `9.4.2 Elements`
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum Nl80211Element {
    Ssid(String),
    /// Supported rates in units of 500 kb/s, if necessary rounded up to the
    /// next 500 kb/
    SupportedRatesAndSelectors(Vec<Nl80211RateAndSelector>),
    /// Allow channel number identification for STAs.
    Channel(u8),
    Country(Nl80211ElementCountry),
    HtCapability(Nl80211ElementHtCap),
    Rsn(Nl80211ElementRsn),
    /// Vendor specific data.
    Vendor(Vec<u8>),
    Other(u8, Vec<u8>),
}

impl Nl80211Element {
    /// The ID field in IEEE 802.11-2020 `Figure 9-145 Element format`
    pub(crate) fn id(&self) -> u8 {
        match self {
            Self::Ssid(_) => ELEMENT_ID_SSID,
            Self::SupportedRatesAndSelectors(_) => ELEMENT_ID_SUPPORTED_RATES,
            Self::Channel(_) => ELEMENT_ID_CHANNEL,
            Self::Country(_) => ELEMENT_ID_COUNTRY,
            Self::Rsn(_) => ELEMENT_ID_RSN,
            Self::Vendor(_) => ELEMENT_ID_VENDOR,
            Self::HtCapability(_) => ELEMENT_ID_HT_CAP,
            Self::Other(id, _) => *id,
        }
    }

    /// The length field in IEEE 802.11-2020 `Figure 9-145 Element format`
    pub(crate) fn length(&self) -> u8 {
        match self {
            Self::Ssid(v) => v.len() as u8,
            Self::SupportedRatesAndSelectors(v) => v.len() as u8,
            Self::Channel(_) => 1,
            Self::Country(v) => v.buffer_len() as u8,
            Self::Rsn(v) => v.buffer_len() as u8,
            Self::Vendor(v) => v.len() as u8,
            Self::HtCapability(v) => v.buffer_len() as u8,
            Self::Other(_, data) => (data.len()) as u8,
        }
    }
}

impl<T: AsRef<[u8]> + ?Sized> Parseable<T> for Nl80211Element {
    fn parse(buf: &T) -> Result<Self, DecodeError> {
        let buf = buf.as_ref();
        if buf.len() < 2 {
            return Err(
                format!("Invalid length of Nl80211Element {buf:?}").into()
            );
        }
        let id = buf[0];
        let length = buf[1];
        let payload = &buf[2..length as usize + 2];
        Ok(match id {
            ELEMENT_ID_SSID => Self::Ssid(
                parse_string(payload)
                    .context(format!("Invalid SSID {payload:?}"))?,
            ),
            ELEMENT_ID_SUPPORTED_RATES => Self::SupportedRatesAndSelectors(
                payload
                    .iter()
                    .map(|d| Nl80211RateAndSelector::from(*d))
                    .collect(),
            ),
            ELEMENT_ID_CHANNEL => Self::Channel(parse_u8(payload).context(
                format!("Invalid DSSS(channel) element {payload:?}"),
            )?),
            ELEMENT_ID_COUNTRY => {
                Self::Country(Nl80211ElementCountry::parse(payload)?)
            }
            ELEMENT_ID_RSN => Self::Rsn(Nl80211ElementRsn::parse(payload)?),
            ELEMENT_ID_VENDOR => Self::Vendor(payload.to_vec()),
            ELEMENT_ID_HT_CAP => {
                Self::HtCapability(Nl80211ElementHtCap::parse(payload)?)
            }
            _ => Self::Other(id, payload.to_vec()),
        })
    }
}

impl Emitable for Nl80211Element {
    fn buffer_len(&self) -> usize {
        self.length() as usize + 2
    }

    fn emit(&self, buffer: &mut [u8]) {
        buffer[0] = self.id();
        buffer[1] = self.length();
        let payload = &mut buffer[2..self.length() as usize + 2];
        match self {
            Self::Ssid(s) => {
                // IEEE 802.11-2020 indicate it is optional to have NULL
                // terminator for this string.
                payload.copy_from_slice(s.as_bytes());
            }
            Self::SupportedRatesAndSelectors(v) => {
                let raw: Vec<u8> =
                    v.as_slice().iter().map(|v| u8::from(*v)).collect();
                payload.copy_from_slice(raw.as_slice());
            }
            Self::Channel(v) => payload[0] = *v,
            Self::Country(v) => v.emit(payload),
            Self::Rsn(v) => v.emit(payload),
            Self::Vendor(v) => payload[..v.len()].copy_from_slice(v.as_slice()),
            Self::HtCapability(v) => v.emit(payload),
            Self::Other(_, data) => {
                payload.copy_from_slice(data.as_slice());
            }
        }
    }
}

const BSS_MEMBERSHIP_SELECTOR_SAE_HASH: u8 = 123;
const BSS_MEMBERSHIP_SELECTOR_EPD: u8 = 124;
const BSS_MEMBERSHIP_SELECTOR_GLK: u8 = 125;
const BSS_MEMBERSHIP_SELECTOR_VHT_PHY: u8 = 126;
const BSS_MEMBERSHIP_SELECTOR_HT_PHY: u8 = 127;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum Nl80211RateAndSelector {
    /// BSS basic rate in units of 500 kb/s, if necessary rounded up to the
    /// next 500 kbs.
    BssBasicRateSet(u8),
    /// Rate in units of 500 kb/s, if necessary rounded up to the next 500 kbs.
    Rate(u8),
    SelectorHt,
    SelectorVht,
    /// Indicates that support for the mandatory features of 11.50 is required
    /// in order to join the BSS that was the source of the Supported Rates and
    /// BSS Membership Selectors element or Extended Supported Rates and BSS
    /// Membership Selectors element containing this value.
    SelectorGlk,
    /// Indicates that support for EPD is required in order to join the BSS
    /// that was the source of the Supported Rates and BSS Membership
    /// Selectors element or Extended Supported Rates and BSS Membership
    /// Selectors element containing this value.
    SelectorEpd,
    /// ndicates that support for the direct hashing to element technique in
    /// SAE is required in order to join the BSS.
    SelectorSaeHash,
}

impl From<u8> for Nl80211RateAndSelector {
    fn from(d: u8) -> Self {
        const MSB_MASK: u8 = 0b1000_0000;
        let msb: bool = (d & MSB_MASK) == MSB_MASK;
        let value = d & !MSB_MASK;
        if msb {
            match value {
                BSS_MEMBERSHIP_SELECTOR_SAE_HASH => Self::SelectorSaeHash,
                BSS_MEMBERSHIP_SELECTOR_EPD => Self::SelectorEpd,
                BSS_MEMBERSHIP_SELECTOR_GLK => Self::SelectorGlk,
                BSS_MEMBERSHIP_SELECTOR_VHT_PHY => Self::SelectorVht,
                BSS_MEMBERSHIP_SELECTOR_HT_PHY => Self::SelectorHt,
                _ => Self::BssBasicRateSet(value),
            }
        } else {
            Self::Rate(value)
        }
    }
}

impl From<Nl80211RateAndSelector> for u8 {
    fn from(v: Nl80211RateAndSelector) -> u8 {
        const MSB: u8 = 0b1000_0000;
        match v {
            Nl80211RateAndSelector::BssBasicRateSet(r) => r & !MSB | MSB,
            Nl80211RateAndSelector::SelectorHt => {
                BSS_MEMBERSHIP_SELECTOR_HT_PHY | MSB
            }
            Nl80211RateAndSelector::SelectorVht => {
                BSS_MEMBERSHIP_SELECTOR_VHT_PHY | MSB
            }
            Nl80211RateAndSelector::SelectorGlk => {
                BSS_MEMBERSHIP_SELECTOR_GLK | MSB
            }
            Nl80211RateAndSelector::SelectorEpd => {
                BSS_MEMBERSHIP_SELECTOR_EPD | MSB
            }
            Nl80211RateAndSelector::SelectorSaeHash => {
                BSS_MEMBERSHIP_SELECTOR_SAE_HASH | MSB
            }
            Nl80211RateAndSelector::Rate(r) => r,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct Nl80211ElementCountry {
    pub country: String,
    pub environment: Nl80211ElementCountryEnvironment,
    pub triplets: Vec<Nl80211ElementCountryTriplet>,
}

impl<T: AsRef<[u8]> + ?Sized> Parseable<T> for Nl80211ElementCountry {
    fn parse(buf: &T) -> Result<Self, DecodeError> {
        let buf = buf.as_ref();
        // IEEE 802.11-2020 said the minimum size of this element is 8 octets.
        if buf.len() < 6 {
            return Err(format!(
                "Buffer for Nl80211ElementCountry is smaller \
                than mandatory 6 byte: {buf:?}"
            )
            .into());
        }
        let country = String::from_utf8(buf[0..2].to_vec()).map_err(|e| {
            DecodeError::from(format!(
                "Invalid country string {:?}: {e}",
                &buf[0..2]
            ))
        })?;
        let environment = Nl80211ElementCountryEnvironment::from(buf[2]);
        let mut triplets: Vec<Nl80211ElementCountryTriplet> = Vec::new();
        for i in 0..((buf.len() - 3) / 3) {
            let payload = &buf[(i + 1) * 3..(i + 2) * 3];
            triplets.push(Nl80211ElementCountryTriplet::parse(payload)?);
        }
        Ok(Self {
            country,
            environment,
            triplets,
        })
    }
}

impl Emitable for Nl80211ElementCountry {
    fn buffer_len(&self) -> usize {
        (self.triplets.len() * 3 + 3).div_ceil(2) * 2
    }

    fn emit(&self, buffer: &mut [u8]) {
        if self.country.len() != 2 {
            log::warn!(
                "Invalid country string {} for Nl80211ElementCountry, \
                should be 2 ASCII characters",
                self.country
            );
        } else {
            buffer[0] = self.country.as_bytes()[0];
            buffer[1] = self.country.as_bytes()[1];
        }
        buffer[2] = self.environment.into();
        for (i, triplet) in self.triplets.as_slice().iter().enumerate() {
            triplet.emit(&mut buffer[(i + 1) * 3..(i + 2) * 3]);
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum Nl80211ElementCountryEnvironment {
    Indoor,
    Outdoor,
    IndoorAndOutdoor,
    Noncountry,
    Other(u8),
}

impl From<Nl80211ElementCountryEnvironment> for u8 {
    fn from(v: Nl80211ElementCountryEnvironment) -> u8 {
        match v {
            Nl80211ElementCountryEnvironment::IndoorAndOutdoor => b' ',
            Nl80211ElementCountryEnvironment::Indoor => b'I',
            Nl80211ElementCountryEnvironment::Outdoor => b'O',
            Nl80211ElementCountryEnvironment::Noncountry => b'X',
            Nl80211ElementCountryEnvironment::Other(d) => d,
        }
    }
}

impl From<u8> for Nl80211ElementCountryEnvironment {
    fn from(d: u8) -> Self {
        match d {
            b' ' => Self::IndoorAndOutdoor,
            b'I' => Self::Indoor,
            b'O' => Self::Outdoor,
            b'X' => Self::Noncountry,
            _ => Self::Other(d),
        }
    }
}

const IEEE80211_COUNTRY_EXTENSION_ID: u8 = 201;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum Nl80211ElementCountryTriplet {
    Subband(Nl80211ElementSubBand),
    Operating(Nl80211ElementOperating),
}

impl Emitable for Nl80211ElementCountryTriplet {
    fn buffer_len(&self) -> usize {
        3
    }

    fn emit(&self, buffer: &mut [u8]) {
        match self {
            Self::Subband(v) => v.emit(buffer),
            Self::Operating(v) => v.emit(buffer),
        }
    }
}

impl Nl80211ElementCountryTriplet {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        if payload.len() != 3 {
            return Err(format!(
                "Invalid buffer for Nl80211ElementCountryTriplet, \
                expecting [u8;3], but got {payload:?}"
            )
            .into());
        }
        if payload[0] >= IEEE80211_COUNTRY_EXTENSION_ID {
            Ok(Self::Operating(Nl80211ElementOperating::from([
                payload[0], payload[1], payload[2],
            ])))
        } else {
            Ok(Self::Subband(Nl80211ElementSubBand::from([
                payload[0], payload[1], payload[2],
            ])))
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Nl80211ElementSubBand {
    pub channel_start: u8,
    pub channel_count: u8,
    /// The Maximum Transmit Power Level field indicates the maximum power, in
    /// dBm, allowed to be transmitted
    pub max_power_level: i8,
}

impl Emitable for Nl80211ElementSubBand {
    fn buffer_len(&self) -> usize {
        3
    }

    fn emit(&self, buffer: &mut [u8]) {
        buffer[0] = self.channel_start;
        buffer[1] = self.channel_count;
        buffer[2] = self.max_power_level as u8;
    }
}

impl From<[u8; 3]> for Nl80211ElementSubBand {
    fn from(buf: [u8; 3]) -> Self {
        Self {
            channel_start: buf[0],
            channel_count: buf[1],
            max_power_level: buf[2] as i8,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Nl80211ElementOperating {
    pub extention_id: u8,
    pub operating_class: u8,
    /// The `aAirPropagationTime` is `coverage_class` * 3 in μs for range
    /// between 0 - 31. Bigger than 31 is reserved.
    pub coverage_class: u8,
}

impl Emitable for Nl80211ElementOperating {
    fn buffer_len(&self) -> usize {
        3
    }

    fn emit(&self, buffer: &mut [u8]) {
        buffer[0] = self.extention_id;
        buffer[1] = self.operating_class;
        buffer[2] = self.coverage_class;
    }
}

impl From<[u8; 3]> for Nl80211ElementOperating {
    fn from(buf: [u8; 3]) -> Self {
        Self {
            extention_id: buf[0],
            operating_class: buf[1],
            coverage_class: buf[2],
        }
    }
}

/// Robust Security Network Element
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct Nl80211ElementRsn {
    pub version: u16,
    pub group_cipher: Option<Nl80211CipherSuite>,
    pub pairwise_ciphers: Vec<Nl80211CipherSuite>,
    /// Authentication Key Management(AKM) suits
    pub akm_suits: Vec<Nl80211AkmSuite>,
    pub rsn_capbilities: Option<Nl80211RsnCapbilities>,
    pub pmkids: Vec<Nl80211Pmkid>,
    pub group_mgmt_cipher: Option<Nl80211CipherSuite>,
}

impl Nl80211ElementRsn {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        if payload.len() != 2 && payload.len() < 8 {
            return Err(format!(
                "Invalid buffer length of Nl80211ElementRsn, \
                expecting 2 or bigger than 7, but got {payload:?}"
            )
            .into());
        }
        let mut ret = Self {
            version: u16::from_le_bytes([payload[0], payload[1]]),
            ..Default::default()
        };

        let mut offset = 2;

        if offset >= payload.len() {
            return Ok(ret);
        }

        ret.group_cipher = Some(Nl80211CipherSuite::parse(
            &payload[offset..offset + Nl80211CipherSuite::LENGTH],
        )?);
        offset += Nl80211CipherSuite::LENGTH;

        if offset >= payload.len() || offset + 2 >= payload.len() {
            return Ok(ret);
        }
        let pairwise_cipher_count =
            u16::from_le_bytes([payload[offset], payload[offset + 1]]) as usize;
        offset += 2;
        if offset >= payload.len() {
            return Ok(ret);
        }

        for _ in 0..pairwise_cipher_count {
            if offset + Nl80211CipherSuite::LENGTH >= payload.len() {
                return Ok(ret);
            }
            ret.pairwise_ciphers.push(Nl80211CipherSuite::parse(
                &payload[offset..offset + Nl80211CipherSuite::LENGTH],
            )?);
            offset += Nl80211CipherSuite::LENGTH;
        }

        if offset >= payload.len() || offset + 2 >= payload.len() {
            return Ok(ret);
        }
        let akm_count =
            u16::from_le_bytes([payload[offset], payload[offset + 1]]) as usize;
        offset += 2;
        if offset >= payload.len() {
            return Ok(ret);
        }
        for _ in 0..akm_count {
            if offset + Nl80211AkmSuite::LENGTH >= payload.len() {
                return Ok(ret);
            }
            ret.akm_suits.push(Nl80211AkmSuite::parse(
                &payload[offset..offset + Nl80211AkmSuite::LENGTH],
            )?);
            offset += Nl80211AkmSuite::LENGTH;
        }
        if offset >= payload.len() || offset + 2 >= payload.len() {
            return Ok(ret);
        }

        ret.rsn_capbilities =
            Some(Nl80211RsnCapbilities::parse(&payload[offset..offset + 2])?);
        offset += 2;

        if offset >= payload.len() || offset + 2 >= payload.len() {
            return Ok(ret);
        }
        let pmkids_count =
            u16::from_le_bytes([payload[offset], payload[offset + 1]]) as usize;
        offset += 2;
        if offset >= payload.len() {
            return Ok(ret);
        }
        for _ in 0..pmkids_count {
            if offset + Nl80211Pmkid::LENGTH >= payload.len() {
                return Ok(ret);
            }
            ret.pmkids.push(Nl80211Pmkid::parse(
                &payload[offset..offset + Nl80211Pmkid::LENGTH],
            )?);
            offset += Nl80211Pmkid::LENGTH;
        }

        if offset >= payload.len()
            || offset + Nl80211CipherSuite::LENGTH >= payload.len()
        {
            return Ok(ret);
        }

        ret.group_mgmt_cipher = Some(Nl80211CipherSuite::parse(
            &payload[offset..offset + Nl80211CipherSuite::LENGTH],
        )?);

        Ok(ret)
    }
}

impl Emitable for Nl80211ElementRsn {
    fn buffer_len(&self) -> usize {
        // version field
        let mut len = 2usize;
        if self.group_cipher.is_none() {
            return len;
        } else {
            len += Nl80211CipherSuite::LENGTH;
        }

        if self.pairwise_ciphers.is_empty() {
            return len;
        } else {
            len += 2 + self.pairwise_ciphers.len() * Nl80211CipherSuite::LENGTH;
        }

        if self.akm_suits.is_empty() {
            return len;
        } else {
            len += 2 + self.akm_suits.len() * Nl80211AkmSuite::LENGTH;
        }

        if self.rsn_capbilities.is_none() {
            return len;
        } else {
            len += 2;
        }

        if self.pmkids.is_empty() {
            return len;
        } else {
            len += 2 + self.pmkids.len() * Nl80211Pmkid::LENGTH;
        }
        if self.group_mgmt_cipher.is_none() {
            return len;
        } else {
            len += Nl80211CipherSuite::LENGTH;
        }

        len
    }

    fn emit(&self, buffer: &mut [u8]) {
        write_u16_le(&mut buffer[0..2], self.version);
        if let Some(g) = self.group_cipher {
            write_u32_le(&mut buffer[2..6], u32::from(g));
            write_u16_le(&mut buffer[6..8], self.pairwise_ciphers.len() as u16);
        }
        for (i, cipher) in self.pairwise_ciphers.as_slice().iter().enumerate() {
            write_u32_le(
                &mut buffer[(8 + i * 4)..(12 + i * 4)],
                u32::from(*cipher),
            );
        }
    }
}

const IEEE_80211_OUI: u32 = 0x00ac0f00;
const CIPHER_USE_GROUP: u32 = IEEE_80211_OUI;
const CIPHER_WEP_40: u32 = IEEE_80211_OUI | 1 << 24;
const CIPHER_TKIP: u32 = IEEE_80211_OUI | 2 << 24;
const CIPHER_CCMP_128: u32 = IEEE_80211_OUI | 4 << 24;
const CIPHER_WEP_104: u32 = IEEE_80211_OUI | 5 << 24;
const CIPHER_BIP_CMAC_128: u32 = IEEE_80211_OUI | 6 << 24;
const CIPHER_GROUP_ADDRESSED_TRACFFIC_NOT_ALLOWED: u32 =
    IEEE_80211_OUI | 7 << 24;
const CIPHER_GCMP_128: u32 = IEEE_80211_OUI | 8 << 24;
const CIPHER_GCMP_256: u32 = IEEE_80211_OUI | 9 << 24;
const CIPHER_CCMP_256: u32 = IEEE_80211_OUI | 10 << 24;
const CIPHER_BIP_GMAC_128: u32 = IEEE_80211_OUI | 11 << 24;
const CIPHER_BIP_GMAC_256: u32 = IEEE_80211_OUI | 12 << 24;
const CIPHER_BIP_CMAC_256: u32 = IEEE_80211_OUI | 13 << 24;

#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
#[non_exhaustive]
pub enum Nl80211CipherSuite {
    UseGroup,
    Wep40,
    Tkip,
    // The 802.11-2020 said only non-DMG default to CCMP-128.
    // But considering 60G 802.11ad(DMG) is rarely used, it is reasonable to
    // assume Ccmp128 is default
    #[default]
    Ccmp128,
    Wep104,
    BipCmac128,
    GroupAddressedTrafficNotAllowed,
    Gcmp128,
    Gcmp256,
    Ccmp256,
    BipGmac128,
    BipGmac256,
    BipCmac256,
    Other(u32),
}

impl From<u32> for Nl80211CipherSuite {
    fn from(d: u32) -> Self {
        match d {
            CIPHER_USE_GROUP => Self::UseGroup,
            CIPHER_WEP_40 => Self::Wep40,
            CIPHER_TKIP => Self::Tkip,
            CIPHER_CCMP_128 => Self::Ccmp128,
            CIPHER_WEP_104 => Self::Wep104,
            CIPHER_BIP_CMAC_128 => Self::BipCmac128,
            CIPHER_GROUP_ADDRESSED_TRACFFIC_NOT_ALLOWED => {
                Self::GroupAddressedTrafficNotAllowed
            }
            CIPHER_GCMP_128 => Self::Gcmp128,
            CIPHER_GCMP_256 => Self::Gcmp256,
            CIPHER_CCMP_256 => Self::Ccmp256,
            CIPHER_BIP_GMAC_128 => Self::BipGmac128,
            CIPHER_BIP_GMAC_256 => Self::BipGmac256,
            CIPHER_BIP_CMAC_256 => Self::BipCmac256,
            _ => Self::Other(d),
        }
    }
}

impl From<Nl80211CipherSuite> for u32 {
    fn from(v: Nl80211CipherSuite) -> u32 {
        match v {
            Nl80211CipherSuite::UseGroup => CIPHER_USE_GROUP,
            Nl80211CipherSuite::Wep40 => CIPHER_WEP_40,
            Nl80211CipherSuite::Tkip => CIPHER_TKIP,
            Nl80211CipherSuite::Ccmp128 => CIPHER_CCMP_128,
            Nl80211CipherSuite::Wep104 => CIPHER_WEP_104,
            Nl80211CipherSuite::BipCmac128 => CIPHER_BIP_CMAC_128,
            Nl80211CipherSuite::GroupAddressedTrafficNotAllowed => {
                CIPHER_GROUP_ADDRESSED_TRACFFIC_NOT_ALLOWED
            }
            Nl80211CipherSuite::Gcmp128 => CIPHER_GCMP_128,
            Nl80211CipherSuite::Gcmp256 => CIPHER_GCMP_256,
            Nl80211CipherSuite::Ccmp256 => CIPHER_CCMP_256,
            Nl80211CipherSuite::BipGmac128 => CIPHER_BIP_GMAC_128,
            Nl80211CipherSuite::BipGmac256 => CIPHER_BIP_GMAC_256,
            Nl80211CipherSuite::BipCmac256 => CIPHER_BIP_CMAC_256,
            Nl80211CipherSuite::Other(d) => d,
        }
    }
}

impl Nl80211CipherSuite {
    pub const LENGTH: usize = 4;

    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        if payload.len() < 4 {
            Err(format!(
                "Invalid buffer length for Nl80211CipherSuite, \
                expecting 4, but got {payload:?}"
            )
            .into())
        } else {
            Ok(u32::from_le_bytes([
                payload[0], payload[1], payload[2], payload[3],
            ])
            .into())
        }
    }
}
const AKM_1X: u32 = IEEE_80211_OUI | 1 << 24;
const AKM_PSK: u32 = IEEE_80211_OUI | 2 << 24;
const AKM_FT_1X: u32 = IEEE_80211_OUI | 3 << 24;
const AKM_FT_PSK: u32 = IEEE_80211_OUI | 4 << 24;
const AKM_1X_SHA256: u32 = IEEE_80211_OUI | 5 << 24;
const AKM_PSK_SHA256: u32 = IEEE_80211_OUI | 6 << 24;
const AKM_TDLS: u32 = IEEE_80211_OUI | 7 << 24;
const AKM_SAE: u32 = IEEE_80211_OUI | 8 << 24;
const AKM_FT_SAE: u32 = IEEE_80211_OUI | 9 << 24;
const AKM_AP_PEER_KEY: u32 = IEEE_80211_OUI | 10 << 24;
const AKM_1X_SUITB: u32 = IEEE_80211_OUI | 11 << 24;
const AKM_1X_CNSA: u32 = IEEE_80211_OUI | 12 << 24;
const AKM_FT_1X_SHA384: u32 = IEEE_80211_OUI | 13 << 24;
const AKM_FILS_SHA256_AES_SIV256_OR_1X: u32 = IEEE_80211_OUI | 14 << 24;
const AKM_FILS_SHA384_AES_SIV512_OR_1X: u32 = IEEE_80211_OUI | 15 << 24;
const AKM_FT_FILS_SHA256_AES_SIV256_OR_1X: u32 = IEEE_80211_OUI | 16 << 24;
const AKM_FT_FILS_SHA384_AES_SIV512_OR_1X: u32 = IEEE_80211_OUI | 17 << 24;
const AKM_FT_PSK_SHA384: u32 = IEEE_80211_OUI | 19 << 24;
const AKM_PSK_SHA384: u32 = IEEE_80211_OUI | 20 << 24;
const AKM_SAE_GROUP_HASH: u32 = IEEE_80211_OUI | 24 << 24;
const AKM_FT_SAE_GROUP_HASH: u32 = IEEE_80211_OUI | 25 << 24;

/// Authentication Key Management Suite
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum Nl80211AkmSuite {
    Ieee8021x,
    Psk,
    FtIeee8021x,
    FtPsk,
    Ieee8021xSha256,
    PskSha256,
    Tdls,
    Sae,
    FtSae,
    ApPeerKey,
    Ieee8021xSuiteB,
    Ieee8021xCnsa,
    FtIeee8021xSha384,
    FilsSha256AesSiv256OrIeee8021x,
    FilsSha384AesSiv512OrIeee8021x,
    FtFilsSha256AesSiv256OrIeee8021x,
    FtFilsSha384AesSiv512OrIeee8021x,
    FtPskSha384,
    PskSha384,
    // Defined in WPA 3 as 00-0F-AC:24
    SaeGroupDependentHash,
    // Defined in WPA 3 as 00-0F-AC:25
    FtSaeGroupDependentHash,
    Other(u32),
}

impl From<u32> for Nl80211AkmSuite {
    fn from(d: u32) -> Self {
        match d {
            AKM_1X => Self::Ieee8021x,
            AKM_PSK => Self::Psk,
            AKM_FT_1X => Self::FtIeee8021x,
            AKM_FT_PSK => Self::FtPsk,
            AKM_1X_SHA256 => Self::Ieee8021xSha256,
            AKM_PSK_SHA256 => Self::PskSha256,
            AKM_TDLS => Self::Tdls,
            AKM_SAE => Self::Sae,
            AKM_FT_SAE => Self::FtSae,
            AKM_AP_PEER_KEY => Self::ApPeerKey,
            AKM_1X_SUITB => Self::Ieee8021xSuiteB,
            AKM_1X_CNSA => Self::Ieee8021xCnsa,
            AKM_FT_1X_SHA384 => Self::FtIeee8021xSha384,
            AKM_FILS_SHA256_AES_SIV256_OR_1X => {
                Self::FilsSha256AesSiv256OrIeee8021x
            }
            AKM_FILS_SHA384_AES_SIV512_OR_1X => {
                Self::FilsSha384AesSiv512OrIeee8021x
            }
            AKM_FT_FILS_SHA256_AES_SIV256_OR_1X => {
                Self::FtFilsSha256AesSiv256OrIeee8021x
            }
            AKM_FT_FILS_SHA384_AES_SIV512_OR_1X => {
                Self::FtFilsSha384AesSiv512OrIeee8021x
            }
            AKM_FT_PSK_SHA384 => Self::FtPskSha384,
            AKM_PSK_SHA384 => Self::PskSha384,
            AKM_SAE_GROUP_HASH => Self::SaeGroupDependentHash,
            AKM_FT_SAE_GROUP_HASH => Self::FtSaeGroupDependentHash,
            _ => Self::Other(d),
        }
    }
}

impl From<Nl80211AkmSuite> for u32 {
    fn from(v: Nl80211AkmSuite) -> u32 {
        match v {
            Nl80211AkmSuite::Ieee8021x => AKM_1X,
            Nl80211AkmSuite::Psk => AKM_PSK,
            Nl80211AkmSuite::FtIeee8021x => AKM_FT_1X,
            Nl80211AkmSuite::FtPsk => AKM_FT_PSK,
            Nl80211AkmSuite::Ieee8021xSha256 => AKM_1X_SHA256,
            Nl80211AkmSuite::PskSha256 => AKM_PSK_SHA256,
            Nl80211AkmSuite::Tdls => AKM_TDLS,
            Nl80211AkmSuite::Sae => AKM_SAE,
            Nl80211AkmSuite::FtSae => AKM_FT_SAE,
            Nl80211AkmSuite::ApPeerKey => AKM_AP_PEER_KEY,
            Nl80211AkmSuite::Ieee8021xSuiteB => AKM_1X_SUITB,
            Nl80211AkmSuite::Ieee8021xCnsa => AKM_1X_CNSA,
            Nl80211AkmSuite::FtIeee8021xSha384 => AKM_FT_1X_SHA384,
            Nl80211AkmSuite::FilsSha256AesSiv256OrIeee8021x => {
                AKM_FILS_SHA256_AES_SIV256_OR_1X
            }
            Nl80211AkmSuite::FilsSha384AesSiv512OrIeee8021x => {
                AKM_FILS_SHA384_AES_SIV512_OR_1X
            }
            Nl80211AkmSuite::FtFilsSha256AesSiv256OrIeee8021x => {
                AKM_FT_FILS_SHA256_AES_SIV256_OR_1X
            }
            Nl80211AkmSuite::FtFilsSha384AesSiv512OrIeee8021x => {
                AKM_FT_FILS_SHA384_AES_SIV512_OR_1X
            }
            Nl80211AkmSuite::FtPskSha384 => AKM_FT_PSK_SHA384,
            Nl80211AkmSuite::PskSha384 => AKM_PSK_SHA384,
            Nl80211AkmSuite::SaeGroupDependentHash => AKM_SAE_GROUP_HASH,
            Nl80211AkmSuite::FtSaeGroupDependentHash => AKM_FT_SAE_GROUP_HASH,
            Nl80211AkmSuite::Other(d) => d,
        }
    }
}
impl Nl80211AkmSuite {
    pub const LENGTH: usize = 4;

    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        if payload.len() < 4 {
            Err(format!(
                "Invalid buffer length for Nl80211AkmSuite, \
                expecting 4, but got {payload:?}"
            )
            .into())
        } else {
            Ok(u32::from_le_bytes([
                payload[0], payload[1], payload[2], payload[3],
            ])
            .into())
        }
    }
}

const RSN_CAP_PRE_AUTH: u16 = 1 << 0;
const RSN_CAP_NO_PAIRWISE: u16 = 1 << 1;
const RSN_CAP_PTKSA_REPLAY_COUNT_2: u16 = 1 << 2;
const RSN_CAP_PTKSA_REPLAY_COUNT_4: u16 = 1 << 3;
const RSN_CAP_GTKSA_REPLAY_COUNT_2: u16 = 1 << 4;
const RSN_CAP_GTKSA_REPLAY_COUNT_4: u16 = 1 << 5;
const RSN_CAP_MFPR: u16 = 1 << 6;
const RSN_CAP_MFPC: u16 = 1 << 7;
const RSN_CAP_JOINT_MULTI_BAND_RSNA: u16 = 1 << 8;
const RSN_CAP_PEER_KEY_ENABLED: u16 = 1 << 9;
const RSN_CAP_SPP_A_MSDU_CAPABLE: u16 = 1 << 10;
const RSN_CAP_SPP_A_MSDU_REQUIRED: u16 = 1 << 11;
const RSN_CAP_PBAC: u16 = 1 << 12;
const RSN_CAP_EXTENDED_KEY_ID_PTKSA: u16 = 1 << 13;
const RSN_CAP_OCVC: u16 = 1 << 14;

bitflags::bitflags! {
    /// If not bands are set, it means don't care and the device will decide
    /// what to use
    #[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
    #[non_exhaustive]
    pub struct Nl80211RsnCapbilities: u16 {
        /// Indicates the AP support preauthentication.
        const PreAuth = RSN_CAP_PRE_AUTH;
        /// Indicates the STA does not support WEP default key 0 simultaneously
        /// with a pairwise key.
        const NoPairwise = RSN_CAP_NO_PAIRWISE;
        /// When Both PtksaReplayCount2 and PtksaReplayCount4 are set,
        /// it means 16 replay conters per PTKSA.
        /// When Neither PtksaReplayCount2 or PtksaReplayCount4 is set,
        /// it means 1 reply counter per PTKSA
        const PtksaReplayCount2 = RSN_CAP_PTKSA_REPLAY_COUNT_2;
        const PtksaReplayCount4 = RSN_CAP_PTKSA_REPLAY_COUNT_4;
        /// When Both GtksaReplayCount2 and GtksaReplayCount4 are set,
        /// it means 16 replay conters per GTKSA.
        /// When Neither GtksaReplayCount2 or GtksaReplayCount4 is set,
        /// it means 1 reply counter per GTKSA
        const GtksaReplayCount2 = RSN_CAP_GTKSA_REPLAY_COUNT_2;
        const GtksaReplayCount4 = RSN_CAP_GTKSA_REPLAY_COUNT_4;
        /// Indicates STA advertise that protection of robust Management frames
        /// is mandatory
        const Mfpr = RSN_CAP_MFPR;
        /// Indicates STA protection of robust Management frames is enabled.
        const Mfpc = RSN_CAP_MFPC;
        /// Joint Multi-band RSNA.
        /// Indicate a STA supports the Joint Multi-band RSNA.
        const JointMultiBandRsna = RSN_CAP_JOINT_MULTI_BAND_RSNA;
        /// An AP indicate it supports PeerKey handshake
        const PeerKeyEnabled = RSN_CAP_PEER_KEY_ENABLED;
        /// A STA indicate it supports signaling and payload protected A-MSDUs.
        const SppAMsduCapable = RSN_CAP_SPP_A_MSDU_CAPABLE;
        /// A STA indicate it allows only SPP A-MSDUs.
        const SppAMsduRequired = RSN_CAP_SPP_A_MSDU_REQUIRED;
        /// Protected block ack agreement capable.
        const Pbac = RSN_CAP_PBAC;
        /// Extended Key ID for Individually Addressed Frames.
        /// Indicate that the STA supports Key ID values in the range 0 to 1 for
        /// a PTKSA when the cipher suite is CCMP or GCMP.
        /// When unset, indicates that the STA only supports Key ID 0 for a
        /// PTKSA
        const ExtendedKeyIdPtksa = RSN_CAP_EXTENDED_KEY_ID_PTKSA;
        /// Indicates the STA supports operating channel validation by including
        /// Operating Channel Information (OCI) in RSNA exchanges and validates
        /// the information when received from another STA that indicated this
        /// capability.
        const Ocvc = RSN_CAP_OCVC;
        const _ = !0;
    }
}

impl Nl80211RsnCapbilities {
    pub const LENGTH: usize = 2;

    pub fn parse(raw: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self::from_bits_retain(parse_u16_le(raw).context(
            format!("Invalid Nl80211RsnCapbilities payload {raw:?}"),
        )?))
    }
}

impl Emitable for Nl80211RsnCapbilities {
    fn buffer_len(&self) -> usize {
        Self::LENGTH
    }

    fn emit(&self, buffer: &mut [u8]) {
        buffer.copy_from_slice(&self.bits().to_le_bytes())
    }
}

/// Authentication Key Management Suite
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Nl80211Pmkid(pub [u8; 16]);

impl Nl80211Pmkid {
    pub const LENGTH: usize = 16;

    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        if payload.len() < Self::LENGTH {
            Err(format!(
                "Invalid buffer length for Nl80211Pmkid, \
                expecting {}, but got {payload:?}",
                Self::LENGTH
            )
            .into())
        } else {
            let mut raw = [0u8; Self::LENGTH];
            raw.copy_from_slice(&payload[..Self::LENGTH]);
            Ok(Self(raw))
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::macros::test::roundtrip_emit_parse_test;

    roundtrip_emit_parse_test!(
        ssid,
        Nl80211Element,
        Nl80211Element::Ssid("test-ssid".to_owned()),
    );
    roundtrip_emit_parse_test!(
        rates_and_selectors,
        Nl80211Element,
        Nl80211Element::SupportedRatesAndSelectors(vec![
            Nl80211RateAndSelector::BssBasicRateSet(1),
            Nl80211RateAndSelector::Rate(1),
            Nl80211RateAndSelector::SelectorHt,
            Nl80211RateAndSelector::SelectorVht,
            Nl80211RateAndSelector::SelectorGlk,
        ])
    );
    roundtrip_emit_parse_test!(
        channel,
        Nl80211Element,
        Nl80211Element::Channel(7)
    );
    roundtrip_emit_parse_test!(
        country,
        Nl80211Element,
        Nl80211Element::Country(Nl80211ElementCountry {
            country: "DE".to_owned(),
            environment: Nl80211ElementCountryEnvironment::IndoorAndOutdoor,
            triplets: vec![Nl80211ElementCountryTriplet::Subband(
                Nl80211ElementSubBand {
                    channel_start: 1,
                    channel_count: 13,
                    max_power_level: 20,
                }
            )],
        }),
    );
}
