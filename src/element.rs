// SPDX-License-Identifier: MIT

use std::mem::size_of;

use netlink_packet_core::{
    parse_string, parse_u8, DecodeError, Emitable, ErrorContext, Parseable,
};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{
    bytes::{parse_u16_le, write_u16_le, write_u32_le},
    Ieee80211ElementHeCap, Ieee80211ElementHtCap, Ieee80211ElementVhtCap,
};

/// [Ieee80211Elements] Vec
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Ieee80211Elements(pub Vec<Ieee80211Element>);

impl<T: AsRef<[u8]> + ?Sized> Parseable<T> for Ieee80211Elements {
    fn parse(buf: &T) -> Result<Self, DecodeError> {
        let buf = buf.as_ref();
        let mut offset = 0;
        let mut ret = Vec::new();
        // An element that is not complete - trailing bytes that are too
        // short for their Length field - ends the parse.
        while let Ok((header, body)) =
            Ieee80211ElementBuffer::split(&buf[offset..])
        {
            let element = Ieee80211Element::parse_body(header, body)?;
            offset += header.buffer_len();
            ret.push(element);
        }
        Ok(Self(ret))
    }
}

impl Emitable for Ieee80211Elements {
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

impl From<&Vec<Ieee80211Element>> for Ieee80211Elements {
    fn from(d: &Vec<Ieee80211Element>) -> Self {
        Self(d.to_vec())
    }
}

impl From<Ieee80211Elements> for Vec<Ieee80211Element> {
    fn from(v: Ieee80211Elements) -> Vec<Ieee80211Element> {
        v.0
    }
}

// These are `Element IDs` defined in IEEE 802.11-2020
const ELEMENT_ID_SSID: u8 = 0;
const ELEMENT_ID_SUPPORTED_RATES: u8 = 1;
const ELEMENT_ID_CHANNEL: u8 = 3;
const ELEMENT_ID_COUNTRY: u8 = 7;
const ELEMENT_ID_HT_CAP: u8 = 45;
/// Element ID of the RSNE (IEEE 802.11-2020 9.4.2.25).
pub const ELEMENT_ID_RSN: u8 = 48;
/// Element ID of the Mobility Domain element (IEEE 802.11-2020
/// 9.4.2.47).
pub const ELEMENT_ID_MDIE: u8 = 54;
/// Element ID of the Fast BSS Transition element (IEEE 802.11-2020
/// 9.4.2.48).
pub const ELEMENT_ID_FTIE: u8 = 55;
/// Element ID of the RM Enabled Capabilities element (IEEE
/// 802.11-2020 9.4.2.43).
pub const ELEMENT_ID_RM_ENABLED_CAPAB: u8 = 70;
/// Element ID of the Extended Capabilities element (IEEE 802.11-2020
/// 9.4.2.26).
pub const ELEMENT_ID_EXT_CAPAB: u8 = 127;
/// Element ID of the RSNXE (IEEE 802.11-2020 9.4.2.25a).
pub const ELEMENT_ID_RSN_EXT: u8 = 244;
const ELEMENT_ID_VHT_CAP: u8 = 191;
/// Element ID of a vendor specific element (IEEE 802.11-2024
/// `Table 9-77`).
pub const ELEMENT_ID_VENDOR: u8 = 221;
/// Element ID of an extensible element: its body starts with the Element ID
/// Extension field (IEEE 802.11-2024 9.4.2, `Figure 9-208`).
pub const ELEMENT_ID_EXTENSION: u8 = 255;
const ELEMENT_ID_EXTENSION_HE_CAP: u8 = 35;

/// The two-octet header of every information element, IEEE 802.11-2024
/// `Figure 9-208`:
///
/// ```text
/// Element ID (1) | Length (1) | Element ID Extension (0 or 1) | Information
/// ```
///
/// The Element ID Extension field is part of the element body and is present
/// only when the Element ID is [`ELEMENT_ID_EXTENSION`], in which case it is
/// the first body octet; `Length` counts every body octet, including the
/// Element ID Extension field.
///
/// The body is not part of this struct: it is variable length, so parsing an
/// element means keeping it next to the header, as done by [`Self::split`].
#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    Copy,
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
)]
#[repr(C, packed)]
pub struct Ieee80211ElementBuffer {
    /// Element ID, [`ELEMENT_ID_EXTENSION`] for an extensible element.
    pub element_id: u8,
    /// Number of octets following this header: the Element ID Extension
    /// field when present, plus the Information field.
    pub length: u8,
}

impl Ieee80211ElementBuffer {
    /// Number of octets of this header.
    pub const LEN: usize = size_of::<Self>();

    /// The header of an element whose body is `length` octets long.
    pub fn new(element_id: u8, length: u8) -> Self {
        Self { element_id, length }
    }

    /// Split `buf` (the start of an element, `Element ID || Length || body`)
    /// into the element header and the element body.
    ///
    /// `buf` may hold several concatenated elements: only the element at its
    /// start is decoded, and the returned body is cut down to the `Length`
    /// octets, so nothing that follows the element is mistaken for its
    /// Information field. An error is returned when `buf` does not hold the
    /// complete body the Length field promises.
    pub fn split(buf: &[u8]) -> Result<(&Self, &[u8]), DecodeError> {
        let (header, body) = Self::ref_from_prefix(buf)
            .map_err(|_| DecodeError::buffer_too_small(buf.len(), Self::LEN))?;
        let length = header.length as usize;
        if body.len() < length {
            return Err(DecodeError::from(format!(
                "Truncated element: the Length field says {length} octets, \
                 but only {} follow the {}-octet header",
                body.len(),
                Self::LEN
            )));
        }
        Ok((header, &body[..length]))
    }

    /// Total number of octets of the element: this header plus its body.
    pub fn buffer_len(&self) -> usize {
        Self::LEN + self.length as usize
    }

    /// Whether the element carries an Element ID Extension field, i.e.
    /// whether [`Self::element_id`] is [`ELEMENT_ID_EXTENSION`].
    pub fn has_element_id_ext(&self) -> bool {
        self.element_id == ELEMENT_ID_EXTENSION
    }

    /// The Element ID Extension field of an extensible element: the first
    /// octet of its body. `None` when the element is not extensible or the
    /// body is empty.
    pub fn element_id_ext(&self, body: &[u8]) -> Option<u8> {
        if self.has_element_id_ext() {
            body.first().copied()
        } else {
            None
        }
    }
}

/// IEEE 802.11-2024 `9.4.2 Elements`
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum Ieee80211Element {
    Ssid(String),
    /// Supported rates in units of 500 kb/s, if necessary rounded up to the
    /// next 500 kb/
    SupportedRatesAndSelectors(Vec<Ieee80211RateAndSelector>),
    /// Allow channel number identification for STAs.
    Channel(u8),
    Country(Ieee80211ElementCountry),
    HtCapability(Ieee80211ElementHtCap),
    Rsn(Ieee80211ElementRsn),
    /// Extended RSN Capabilities (RSNXE), e.g. the SAE Hash-to-Element
    /// indicator.
    RsnExt(Ieee80211ElementRsnExt),
    VhtCapability(Ieee80211ElementVhtCap),
    /// Vendor specific data.
    Vendor(Vec<u8>),
    HeCapability(Ieee80211ElementHeCap),
    Other(u8, Vec<u8>),
}

impl Ieee80211Element {
    /// The Element ID field of IEEE 802.11-2024 `Figure 9-208`.
    pub(crate) fn id(&self) -> u8 {
        match self {
            Self::Ssid(_) => ELEMENT_ID_SSID,
            Self::SupportedRatesAndSelectors(_) => ELEMENT_ID_SUPPORTED_RATES,
            Self::Channel(_) => ELEMENT_ID_CHANNEL,
            Self::Country(_) => ELEMENT_ID_COUNTRY,
            Self::Rsn(_) => ELEMENT_ID_RSN,
            Self::RsnExt(_) => ELEMENT_ID_RSN_EXT,
            Self::Vendor(_) => ELEMENT_ID_VENDOR,
            Self::HtCapability(_) => ELEMENT_ID_HT_CAP,
            Self::VhtCapability(_) => ELEMENT_ID_VHT_CAP,
            Self::HeCapability(_) => ELEMENT_ID_EXTENSION,
            Self::Other(id, _) => *id,
        }
    }

    /// The Length field of IEEE 802.11-2024 `Figure 9-208`.
    pub(crate) fn length(&self) -> u8 {
        match self {
            Self::Ssid(v) => v.len() as u8,
            Self::SupportedRatesAndSelectors(v) => v.len() as u8,
            Self::Channel(_) => 1,
            Self::Country(v) => v.buffer_len() as u8,
            Self::Rsn(v) => v.buffer_len() as u8,
            Self::RsnExt(v) => v.buffer_len() as u8,
            Self::Vendor(v) => v.len() as u8,
            Self::HtCapability(v) => v.buffer_len() as u8,
            Self::VhtCapability(v) => v.buffer_len() as u8,
            Self::HeCapability(v) => v.buffer_len() as u8,
            Self::Other(_, data) => (data.len()) as u8,
        }
    }

    /// Parse the body of an element whose header was decoded by
    /// [`Ieee80211ElementBuffer::split`].
    ///
    /// `body` holds the `Length` octets that follow the header, including
    /// the Element ID Extension field for extensible elements.
    pub fn parse_body(
        header: &Ieee80211ElementBuffer,
        body: &[u8],
    ) -> Result<Self, DecodeError> {
        Ok(match header.element_id {
            ELEMENT_ID_SSID => Self::Ssid(
                parse_string(body).context(format!("Invalid SSID {body:?}"))?,
            ),
            ELEMENT_ID_SUPPORTED_RATES => Self::SupportedRatesAndSelectors(
                body.iter()
                    .map(|d| Ieee80211RateAndSelector::from(*d))
                    .collect(),
            ),
            ELEMENT_ID_CHANNEL => {
                Self::Channel(parse_u8(body).context(format!(
                    "Invalid DSSS(channel) element {body:?}"
                ))?)
            }
            ELEMENT_ID_COUNTRY => {
                Self::Country(Ieee80211ElementCountry::parse(body)?)
            }
            ELEMENT_ID_RSN => Self::Rsn(Ieee80211ElementRsn::parse(body)?),
            ELEMENT_ID_RSN_EXT => {
                Self::RsnExt(Ieee80211ElementRsnExt::parse(body)?)
            }
            ELEMENT_ID_VENDOR => Self::Vendor(body.to_vec()),
            ELEMENT_ID_HT_CAP => {
                Self::HtCapability(Ieee80211ElementHtCap::parse(body)?)
            }
            ELEMENT_ID_VHT_CAP => {
                Self::VhtCapability(Ieee80211ElementVhtCap::parse(body)?)
            }
            ELEMENT_ID_EXTENSION => match header.element_id_ext(body) {
                Some(ELEMENT_ID_EXTENSION_HE_CAP) => {
                    Self::HeCapability(Ieee80211ElementHeCap::parse(body)?)
                }
                _ => Self::Other(ELEMENT_ID_EXTENSION, body.to_vec()),
            },
            element_id => Self::Other(element_id, body.to_vec()),
        })
    }
}

impl<T: AsRef<[u8]> + ?Sized> Parseable<T> for Ieee80211Element {
    fn parse(buf: &T) -> Result<Self, DecodeError> {
        let buf = buf.as_ref();
        let (header, body) = Ieee80211ElementBuffer::split(buf)?;
        Self::parse_body(header, body)
    }
}

impl Emitable for Ieee80211Element {
    fn buffer_len(&self) -> usize {
        Ieee80211ElementBuffer::LEN + self.length() as usize
    }

    fn emit(&self, buffer: &mut [u8]) {
        let header = Ieee80211ElementBuffer::new(self.id(), self.length());
        buffer[..Ieee80211ElementBuffer::LEN]
            .copy_from_slice(header.as_bytes());
        let buffer = &mut buffer[Ieee80211ElementBuffer::LEN
            ..Ieee80211ElementBuffer::LEN + self.length() as usize];
        match self {
            Self::Ssid(s) => {
                // IEEE 802.11-2020 indicate it is optional to have NULL
                // terminator for this string.
                buffer.copy_from_slice(s.as_bytes());
            }
            Self::SupportedRatesAndSelectors(v) => {
                let raw: Vec<u8> =
                    v.as_slice().iter().map(|v| u8::from(*v)).collect();
                buffer.copy_from_slice(raw.as_slice());
            }
            Self::Channel(v) => buffer[0] = *v,
            Self::Country(v) => v.emit(buffer),
            Self::Rsn(v) => v.emit(buffer),
            Self::RsnExt(v) => v.emit(buffer),
            Self::Vendor(v) => buffer[..v.len()].copy_from_slice(v.as_slice()),
            Self::HtCapability(v) => v.emit(buffer),
            Self::VhtCapability(v) => v.emit(buffer),
            Self::HeCapability(v) => v.emit(buffer),
            Self::Other(_, data) => {
                buffer.copy_from_slice(data.as_slice());
            }
        }
    }
}

const BSS_MEMBERSHIP_SELECTOR_SAE_HASH: u8 = 123;
const BSS_MEMBERSHIP_SELECTOR_EPD: u8 = 124;
const BSS_MEMBERSHIP_SELECTOR_GLK: u8 = 125;
const BSS_MEMBERSHIP_SELECTOR_VHT_PHY: u8 = 126;
const BSS_MEMBERSHIP_SELECTOR_HT_PHY: u8 = 127;
const BSS_MEMBERSHIP_SELECTOR_HE_PHY: u8 = 122;
const BSS_MEMBERSHIP_SELECTOR_EHT_PHY: u8 = 121;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum Ieee80211RateAndSelector {
    /// BSS basic rate in units of 500 kb/s, if necessary rounded up to the
    /// next 500 kbs.
    BssBasicRateSet(u8),
    /// Rate in units of 500 kb/s, if necessary rounded up to the next 500 kbs.
    Rate(u8),
    SelectorHt,
    SelectorVht,
    /// Indicates that support for the mandatory features of Clause 27 (HE
    /// PHY) is required in order to join the BSS.
    SelectorHe,
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
    /// Indicates that support for the mandatory features of Clause 36 (EHT
    /// PHY) is required in order to join the BSS (802.11be Table 9-131).
    SelectorEht,
}

impl From<u8> for Ieee80211RateAndSelector {
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
                BSS_MEMBERSHIP_SELECTOR_HE_PHY => Self::SelectorHe,
                BSS_MEMBERSHIP_SELECTOR_EHT_PHY => Self::SelectorEht,
                _ => Self::BssBasicRateSet(value),
            }
        } else {
            Self::Rate(value)
        }
    }
}

impl From<Ieee80211RateAndSelector> for u8 {
    fn from(v: Ieee80211RateAndSelector) -> u8 {
        const MSB: u8 = 0b1000_0000;
        match v {
            Ieee80211RateAndSelector::BssBasicRateSet(r) => r & !MSB | MSB,
            Ieee80211RateAndSelector::SelectorHt => {
                BSS_MEMBERSHIP_SELECTOR_HT_PHY | MSB
            }
            Ieee80211RateAndSelector::SelectorVht => {
                BSS_MEMBERSHIP_SELECTOR_VHT_PHY | MSB
            }
            Ieee80211RateAndSelector::SelectorHe => {
                BSS_MEMBERSHIP_SELECTOR_HE_PHY | MSB
            }
            Ieee80211RateAndSelector::SelectorEht => {
                BSS_MEMBERSHIP_SELECTOR_EHT_PHY | MSB
            }
            Ieee80211RateAndSelector::SelectorGlk => {
                BSS_MEMBERSHIP_SELECTOR_GLK | MSB
            }
            Ieee80211RateAndSelector::SelectorEpd => {
                BSS_MEMBERSHIP_SELECTOR_EPD | MSB
            }
            Ieee80211RateAndSelector::SelectorSaeHash => {
                BSS_MEMBERSHIP_SELECTOR_SAE_HASH | MSB
            }
            Ieee80211RateAndSelector::Rate(r) => r,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct Ieee80211ElementCountry {
    pub country: String,
    pub environment: Ieee80211ElementCountryEnvironment,
    pub triplets: Vec<Ieee80211ElementCountryTriplet>,
}

impl<T: AsRef<[u8]> + ?Sized> Parseable<T> for Ieee80211ElementCountry {
    fn parse(buf: &T) -> Result<Self, DecodeError> {
        let buf = buf.as_ref();
        // IEEE 802.11-2024 9.4.2.7: the minimum size is 6 octets
        // (country string + environment) followed by triplets.
        if buf.len() < 6 {
            return Err(format!(
                "Buffer for Ieee80211ElementCountry is smaller \
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
        let environment = Ieee80211ElementCountryEnvironment::from(buf[2]);
        let mut triplets: Vec<Ieee80211ElementCountryTriplet> = Vec::new();
        for i in 0..((buf.len() - 3) / 3) {
            let payload = &buf[(i + 1) * 3..(i + 2) * 3];
            triplets.push(Ieee80211ElementCountryTriplet::parse(payload)?);
        }
        Ok(Self {
            country,
            environment,
            triplets,
        })
    }
}

impl Emitable for Ieee80211ElementCountry {
    fn buffer_len(&self) -> usize {
        (self.triplets.len() * 3 + 3).div_ceil(2) * 2
    }

    fn emit(&self, buffer: &mut [u8]) {
        if self.country.len() != 2 {
            log::warn!(
                "Invalid country string {} for Ieee80211ElementCountry, \
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
        // IEEE 802.11-2024 9.4.2.7: a single zero padding octet is added when
        // needed so that the element length is evenly divisible by 2.
        let data_len = 3 + self.triplets.len() * 3;
        if data_len % 2 == 1 {
            buffer[data_len] = 0;
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum Ieee80211ElementCountryEnvironment {
    Indoor,
    Outdoor,
    IndoorAndOutdoor,
    Noncountry,
    Other(u8),
}

impl From<Ieee80211ElementCountryEnvironment> for u8 {
    fn from(v: Ieee80211ElementCountryEnvironment) -> u8 {
        match v {
            Ieee80211ElementCountryEnvironment::IndoorAndOutdoor => b' ',
            Ieee80211ElementCountryEnvironment::Indoor => b'I',
            Ieee80211ElementCountryEnvironment::Outdoor => b'O',
            Ieee80211ElementCountryEnvironment::Noncountry => b'X',
            Ieee80211ElementCountryEnvironment::Other(d) => d,
        }
    }
}

impl From<u8> for Ieee80211ElementCountryEnvironment {
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
pub enum Ieee80211ElementCountryTriplet {
    Subband(Ieee80211ElementSubBand),
    Operating(Ieee80211ElementOperating),
}

impl Emitable for Ieee80211ElementCountryTriplet {
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

impl Ieee80211ElementCountryTriplet {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        if payload.len() != 3 {
            return Err(format!(
                "Invalid buffer for Ieee80211ElementCountryTriplet, \
                expecting [u8;3], but got {payload:?}"
            )
            .into());
        }
        if payload[0] >= IEEE80211_COUNTRY_EXTENSION_ID {
            Ok(Self::Operating(Ieee80211ElementOperating::from([
                payload[0], payload[1], payload[2],
            ])))
        } else {
            Ok(Self::Subband(Ieee80211ElementSubBand::from([
                payload[0], payload[1], payload[2],
            ])))
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Ieee80211ElementSubBand {
    pub channel_start: u8,
    pub channel_count: u8,
    /// The Maximum Transmit Power Level field indicates the maximum power, in
    /// dBm, allowed to be transmitted
    pub max_power_level: i8,
}

impl Emitable for Ieee80211ElementSubBand {
    fn buffer_len(&self) -> usize {
        3
    }

    fn emit(&self, buffer: &mut [u8]) {
        buffer[0] = self.channel_start;
        buffer[1] = self.channel_count;
        buffer[2] = self.max_power_level as u8;
    }
}

impl From<[u8; 3]> for Ieee80211ElementSubBand {
    fn from(buf: [u8; 3]) -> Self {
        Self {
            channel_start: buf[0],
            channel_count: buf[1],
            max_power_level: buf[2] as i8,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Ieee80211ElementOperating {
    pub extension_id: u8,
    pub operating_class: u8,
    /// The `aAirPropagationTime` is `coverage_class` * 3 in μs for range
    /// between 0 - 31. Bigger than 31 is reserved.
    pub coverage_class: u8,
}

impl Emitable for Ieee80211ElementOperating {
    fn buffer_len(&self) -> usize {
        3
    }

    fn emit(&self, buffer: &mut [u8]) {
        buffer[0] = self.extension_id;
        buffer[1] = self.operating_class;
        buffer[2] = self.coverage_class;
    }
}

impl From<[u8; 3]> for Ieee80211ElementOperating {
    fn from(buf: [u8; 3]) -> Self {
        Self {
            extension_id: buf[0],
            operating_class: buf[1],
            coverage_class: buf[2],
        }
    }
}

/// Robust Security Network Element
///
/// IEEE 802.11-2024: 9.4.2.23 RSNE
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Ieee80211ElementRsn {
    pub version: u16,
    pub group_cipher: Option<Ieee80211CipherSuite>,
    pub pairwise_ciphers: Vec<Ieee80211CipherSuite>,
    /// Authentication Key Management(AKM) suits
    pub akm_suits: Vec<Ieee80211AkmSuite>,
    pub rsn_capbilities: Option<Ieee80211RsnCapbilities>,
    pub pmkids: Vec<Ieee80211Pmkid>,
    pub group_mgmt_cipher: Option<Ieee80211CipherSuite>,
}

impl Default for Ieee80211ElementRsn {
    fn default() -> Self {
        Self {
            version: 1,
            group_cipher: None,
            pairwise_ciphers: Vec::new(),
            akm_suits: Vec::new(),
            rsn_capbilities: None,
            pmkids: Vec::new(),
            group_mgmt_cipher: None,
        }
    }
}

impl Ieee80211ElementRsn {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        // Per IEEE 802.11-2024 9.4.2.23.1 the RSNE contains up to and
        // including the mandatory 2-octet Version field; every field after it
        // is optional.
        if payload.len() < 2 {
            return Err(format!(
                "Invalid buffer length of Ieee80211ElementRsn, \
                expecting at least 2, but got {payload:?}"
            )
            .into());
        }
        let mut ret = Self {
            version: u16::from_le_bytes([payload[0], payload[1]]),
            ..Default::default()
        };

        let mut offset = 2;

        if offset >= payload.len()
            || offset + Ieee80211CipherSuite::LENGTH > payload.len()
        {
            return Ok(ret);
        }

        ret.group_cipher = Some(Ieee80211CipherSuite::parse(
            &payload[offset..offset + Ieee80211CipherSuite::LENGTH],
        )?);
        offset += Ieee80211CipherSuite::LENGTH;

        if offset >= payload.len() || offset + 2 > payload.len() {
            return Ok(ret);
        }
        let pairwise_cipher_count =
            u16::from_le_bytes([payload[offset], payload[offset + 1]]) as usize;
        offset += 2;
        if offset >= payload.len() {
            return Ok(ret);
        }

        for _ in 0..pairwise_cipher_count {
            if offset + Ieee80211CipherSuite::LENGTH > payload.len() {
                return Ok(ret);
            }
            ret.pairwise_ciphers.push(Ieee80211CipherSuite::parse(
                &payload[offset..offset + Ieee80211CipherSuite::LENGTH],
            )?);
            offset += Ieee80211CipherSuite::LENGTH;
        }
        if offset >= payload.len() || offset + 2 > payload.len() {
            return Ok(ret);
        }
        let akm_count =
            u16::from_le_bytes([payload[offset], payload[offset + 1]]) as usize;
        offset += 2;
        if offset >= payload.len() {
            return Ok(ret);
        }
        for _ in 0..akm_count {
            if offset + Ieee80211AkmSuite::LENGTH > payload.len() {
                return Ok(ret);
            }
            ret.akm_suits.push(Ieee80211AkmSuite::parse(
                &payload[offset..offset + Ieee80211AkmSuite::LENGTH],
            )?);
            offset += Ieee80211AkmSuite::LENGTH;
        }
        if offset >= payload.len() || offset + 2 > payload.len() {
            return Ok(ret);
        }

        ret.rsn_capbilities = Some(Ieee80211RsnCapbilities::parse(
            &payload[offset..offset + 2],
        )?);
        offset += 2;

        if offset >= payload.len() || offset + 2 > payload.len() {
            return Ok(ret);
        }
        let pmkids_count =
            u16::from_le_bytes([payload[offset], payload[offset + 1]]) as usize;
        offset += 2;
        if offset >= payload.len() {
            return Ok(ret);
        }
        for _ in 0..pmkids_count {
            if offset + Ieee80211Pmkid::LENGTH > payload.len() {
                return Ok(ret);
            }
            ret.pmkids.push(Ieee80211Pmkid::parse(
                &payload[offset..offset + Ieee80211Pmkid::LENGTH],
            )?);
            offset += Ieee80211Pmkid::LENGTH;
        }

        if offset >= payload.len()
            || offset + Ieee80211CipherSuite::LENGTH > payload.len()
        {
            return Ok(ret);
        }

        ret.group_mgmt_cipher = Some(Ieee80211CipherSuite::parse(
            &payload[offset..offset + Ieee80211CipherSuite::LENGTH],
        )?);
        Ok(ret)
    }
}

impl Emitable for Ieee80211ElementRsn {
    fn buffer_len(&self) -> usize {
        // version field
        let mut len = 2usize;
        if self.group_cipher.is_none() {
            return len;
        } else {
            len += Ieee80211CipherSuite::LENGTH;
        }

        if self.pairwise_ciphers.is_empty() {
            return len;
        } else {
            len +=
                2 + self.pairwise_ciphers.len() * Ieee80211CipherSuite::LENGTH;
        }

        if self.akm_suits.is_empty() {
            return len;
        } else {
            len += 2 + self.akm_suits.len() * Ieee80211AkmSuite::LENGTH;
        }

        if self.rsn_capbilities.is_none() {
            return len;
        } else {
            len += 2;
        }

        if self.pmkids.is_empty() && self.group_mgmt_cipher.is_none() {
            return len;
        }
        // PMKID count is always present once a PMKID list and/or a group
        // management cipher follows the RSN capabilities.
        len += 2 + self.pmkids.len() * Ieee80211Pmkid::LENGTH;

        if self.group_mgmt_cipher.is_some() {
            len += Ieee80211CipherSuite::LENGTH;
        }

        len
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut offset = 0;
        write_u16_le(&mut buffer[0..2], self.version);
        offset += 2;
        if let Some(g) = self.group_cipher {
            write_u32_le(&mut buffer[offset..offset + 4], u32::from(g));
            offset += 4;
            if self.pairwise_ciphers.is_empty() {
                if !self.akm_suits.is_empty()
                    || self.rsn_capbilities.is_some()
                    || !self.pmkids.is_empty()
                    || self.group_mgmt_cipher.is_some()
                {
                    log::warn!(
                        "Ieee80211ElementRsn: fields after the pairwise \
                        cipher suite list are dropped because the pairwise \
                        list is empty"
                    );
                }
                return;
            }
            write_u16_le(
                &mut buffer[offset..offset + 2],
                self.pairwise_ciphers.len() as u16,
            );
            offset += 2;
        }
        for cipher in self.pairwise_ciphers.as_slice().iter() {
            write_u32_le(&mut buffer[offset..offset + 4], u32::from(*cipher));
            offset += 4;
        }
        if !self.akm_suits.is_empty() {
            write_u16_le(
                &mut buffer[offset..offset + 2],
                self.akm_suits.len() as u16,
            );
            offset += 2;
            for akm in self.akm_suits.as_slice() {
                write_u32_le(&mut buffer[offset..offset + 4], u32::from(*akm));
                offset += 4;
            }
        }
        if let Some(rsn_cap) = self.rsn_capbilities {
            write_u16_le(&mut buffer[offset..offset + 2], rsn_cap.bits());
            offset += 2;
        }

        if !self.pmkids.is_empty() || self.group_mgmt_cipher.is_some() {
            write_u16_le(
                &mut buffer[offset..offset + 2],
                self.pmkids.len() as u16,
            );
            offset += 2;
            for pmkid in self.pmkids.as_slice() {
                pmkid.emit(&mut buffer[offset..]);
                offset += Ieee80211Pmkid::LENGTH;
            }
            if let Some(c) = self.group_mgmt_cipher {
                write_u32_le(&mut buffer[offset..offset + 4], u32::from(c));
            }
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
const CIPHER_GROUP_ADDRESSED_TRAFFIC_NOT_ALLOWED: u32 =
    IEEE_80211_OUI | 7 << 24;
const CIPHER_GCMP_128: u32 = IEEE_80211_OUI | 8 << 24;
const CIPHER_GCMP_256: u32 = IEEE_80211_OUI | 9 << 24;
const CIPHER_CCMP_256: u32 = IEEE_80211_OUI | 10 << 24;
const CIPHER_BIP_GMAC_128: u32 = IEEE_80211_OUI | 11 << 24;
const CIPHER_BIP_GMAC_256: u32 = IEEE_80211_OUI | 12 << 24;
const CIPHER_BIP_CMAC_256: u32 = IEEE_80211_OUI | 13 << 24;
// WAPI SMS4 (OUI 00-14-72, suite type 1). Not part of IEEE 802.11-2024
// Table 9-188; the Linux kernel defines it as `WLAN_CIPHER_SUITE_SMS4`.
const CIPHER_SMS4: u32 = 0x01721400;

#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
#[non_exhaustive]
pub enum Ieee80211CipherSuite {
    UseGroup,
    /// Reserved in IEEE 802.11-2024 (Table 9-188); kept for legacy
    /// WPA/WPA2 compatibility.
    Wep40,
    Tkip,
    // The 802.11-2020 said only non-DMG default to CCMP-128.
    // But considering 60G 802.11ad(DMG) is rarely used, it is reasonable to
    // assume Ccmp128 is default
    #[default]
    Ccmp128,
    /// Reserved in IEEE 802.11-2024 (Table 9-188); kept for legacy
    /// WPA/WPA2 compatibility.
    Wep104,
    BipCmac128,
    GroupAddressedTrafficNotAllowed,
    Gcmp128,
    Gcmp256,
    Ccmp256,
    BipGmac128,
    BipGmac256,
    BipCmac256,
    /// WAPI SMS4 (`00-14-72:1`), defined by the kernel as
    /// `WLAN_CIPHER_SUITE_SMS4`.
    Sms4,
    Other(u32),
}

impl From<u32> for Ieee80211CipherSuite {
    fn from(d: u32) -> Self {
        match d {
            CIPHER_USE_GROUP => Self::UseGroup,
            CIPHER_WEP_40 => Self::Wep40,
            CIPHER_TKIP => Self::Tkip,
            CIPHER_CCMP_128 => Self::Ccmp128,
            CIPHER_WEP_104 => Self::Wep104,
            CIPHER_BIP_CMAC_128 => Self::BipCmac128,
            CIPHER_GROUP_ADDRESSED_TRAFFIC_NOT_ALLOWED => {
                Self::GroupAddressedTrafficNotAllowed
            }
            CIPHER_GCMP_128 => Self::Gcmp128,
            CIPHER_GCMP_256 => Self::Gcmp256,
            CIPHER_CCMP_256 => Self::Ccmp256,
            CIPHER_BIP_GMAC_128 => Self::BipGmac128,
            CIPHER_BIP_GMAC_256 => Self::BipGmac256,
            CIPHER_BIP_CMAC_256 => Self::BipCmac256,
            CIPHER_SMS4 => Self::Sms4,
            _ => Self::Other(d),
        }
    }
}

impl From<Ieee80211CipherSuite> for u32 {
    fn from(v: Ieee80211CipherSuite) -> u32 {
        match v {
            Ieee80211CipherSuite::UseGroup => CIPHER_USE_GROUP,
            Ieee80211CipherSuite::Wep40 => CIPHER_WEP_40,
            Ieee80211CipherSuite::Tkip => CIPHER_TKIP,
            Ieee80211CipherSuite::Ccmp128 => CIPHER_CCMP_128,
            Ieee80211CipherSuite::Wep104 => CIPHER_WEP_104,
            Ieee80211CipherSuite::BipCmac128 => CIPHER_BIP_CMAC_128,
            Ieee80211CipherSuite::GroupAddressedTrafficNotAllowed => {
                CIPHER_GROUP_ADDRESSED_TRAFFIC_NOT_ALLOWED
            }
            Ieee80211CipherSuite::Gcmp128 => CIPHER_GCMP_128,
            Ieee80211CipherSuite::Gcmp256 => CIPHER_GCMP_256,
            Ieee80211CipherSuite::Ccmp256 => CIPHER_CCMP_256,
            Ieee80211CipherSuite::BipGmac128 => CIPHER_BIP_GMAC_128,
            Ieee80211CipherSuite::BipGmac256 => CIPHER_BIP_GMAC_256,
            Ieee80211CipherSuite::BipCmac256 => CIPHER_BIP_CMAC_256,
            Ieee80211CipherSuite::Sms4 => CIPHER_SMS4,
            Ieee80211CipherSuite::Other(d) => d,
        }
    }
}

impl Ieee80211CipherSuite {
    pub const LENGTH: usize = 4;

    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        if payload.len() < 4 {
            Err(format!(
                "Invalid buffer length for Ieee80211CipherSuite, \
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
const AKM_FT_1X_SHA384_SUITE_B: u32 = IEEE_80211_OUI | 13 << 24;
const AKM_FILS_SHA256_AES_SIV256_OR_1X: u32 = IEEE_80211_OUI | 14 << 24;
const AKM_FILS_SHA384_AES_SIV512_OR_1X: u32 = IEEE_80211_OUI | 15 << 24;
const AKM_FT_FILS_SHA256_AES_SIV256_OR_1X: u32 = IEEE_80211_OUI | 16 << 24;
const AKM_FT_FILS_SHA384_AES_SIV512_OR_1X: u32 = IEEE_80211_OUI | 17 << 24;
const AKM_OWE: u32 = IEEE_80211_OUI | 18 << 24;
const AKM_FT_PSK_SHA384: u32 = IEEE_80211_OUI | 19 << 24;
const AKM_PSK_SHA384: u32 = IEEE_80211_OUI | 20 << 24;
const AKM_PASN: u32 = IEEE_80211_OUI | 21 << 24;
const AKM_FT_1X_SHA384: u32 = IEEE_80211_OUI | 22 << 24;
const AKM_1X_SHA384: u32 = IEEE_80211_OUI | 23 << 24;
const AKM_SAE_GROUP_HASH: u32 = IEEE_80211_OUI | 24 << 24;
const AKM_FT_SAE_GROUP_HASH: u32 = IEEE_80211_OUI | 25 << 24;

/// Authentication Key Management Suite
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum Ieee80211AkmSuite {
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
    FtIeee8021xSha384SuiteB,
    FilsSha256AesSiv256OrIeee8021x,
    FilsSha384AesSiv512OrIeee8021x,
    FtFilsSha256AesSiv256OrIeee8021x,
    FtFilsSha384AesSiv512OrIeee8021x,
    Owe,
    FtPskSha384,
    PskSha384,
    Pasn,
    FtIeee8021xSha384,
    Ieee8021xSha384,
    // Defined in WPA 3 as 00-0F-AC:24
    SaeGroupDependentHash,
    // Defined in WPA 3 as 00-0F-AC:25
    FtSaeGroupDependentHash,
    Other(u32),
}

impl From<u32> for Ieee80211AkmSuite {
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
            AKM_FT_1X_SHA384_SUITE_B => Self::FtIeee8021xSha384SuiteB,
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
            AKM_OWE => Self::Owe,
            AKM_FT_PSK_SHA384 => Self::FtPskSha384,
            AKM_PSK_SHA384 => Self::PskSha384,
            AKM_PASN => Self::Pasn,
            AKM_FT_1X_SHA384 => Self::FtIeee8021xSha384,
            AKM_1X_SHA384 => Self::Ieee8021xSha384,
            AKM_SAE_GROUP_HASH => Self::SaeGroupDependentHash,
            AKM_FT_SAE_GROUP_HASH => Self::FtSaeGroupDependentHash,
            _ => Self::Other(d),
        }
    }
}

impl From<Ieee80211AkmSuite> for u32 {
    fn from(v: Ieee80211AkmSuite) -> u32 {
        match v {
            Ieee80211AkmSuite::Ieee8021x => AKM_1X,
            Ieee80211AkmSuite::Psk => AKM_PSK,
            Ieee80211AkmSuite::FtIeee8021x => AKM_FT_1X,
            Ieee80211AkmSuite::FtPsk => AKM_FT_PSK,
            Ieee80211AkmSuite::Ieee8021xSha256 => AKM_1X_SHA256,
            Ieee80211AkmSuite::PskSha256 => AKM_PSK_SHA256,
            Ieee80211AkmSuite::Tdls => AKM_TDLS,
            Ieee80211AkmSuite::Sae => AKM_SAE,
            Ieee80211AkmSuite::FtSae => AKM_FT_SAE,
            Ieee80211AkmSuite::ApPeerKey => AKM_AP_PEER_KEY,
            Ieee80211AkmSuite::Ieee8021xSuiteB => AKM_1X_SUITB,
            Ieee80211AkmSuite::Ieee8021xCnsa => AKM_1X_CNSA,
            Ieee80211AkmSuite::FtIeee8021xSha384SuiteB => {
                AKM_FT_1X_SHA384_SUITE_B
            }
            Ieee80211AkmSuite::FilsSha256AesSiv256OrIeee8021x => {
                AKM_FILS_SHA256_AES_SIV256_OR_1X
            }
            Ieee80211AkmSuite::FilsSha384AesSiv512OrIeee8021x => {
                AKM_FILS_SHA384_AES_SIV512_OR_1X
            }
            Ieee80211AkmSuite::FtFilsSha256AesSiv256OrIeee8021x => {
                AKM_FT_FILS_SHA256_AES_SIV256_OR_1X
            }
            Ieee80211AkmSuite::FtFilsSha384AesSiv512OrIeee8021x => {
                AKM_FT_FILS_SHA384_AES_SIV512_OR_1X
            }
            Ieee80211AkmSuite::Owe => AKM_OWE,
            Ieee80211AkmSuite::FtPskSha384 => AKM_FT_PSK_SHA384,
            Ieee80211AkmSuite::PskSha384 => AKM_PSK_SHA384,
            Ieee80211AkmSuite::Pasn => AKM_PASN,
            Ieee80211AkmSuite::FtIeee8021xSha384 => AKM_FT_1X_SHA384,
            Ieee80211AkmSuite::Ieee8021xSha384 => AKM_1X_SHA384,
            Ieee80211AkmSuite::SaeGroupDependentHash => AKM_SAE_GROUP_HASH,
            Ieee80211AkmSuite::FtSaeGroupDependentHash => AKM_FT_SAE_GROUP_HASH,
            Ieee80211AkmSuite::Other(d) => d,
        }
    }
}
impl Ieee80211AkmSuite {
    pub const LENGTH: usize = 4;

    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        if payload.len() < 4 {
            Err(format!(
                "Invalid buffer length for Ieee80211AkmSuite, \
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
const RSN_CAP_PTKSA_REPLAY_COUNT_2: u16 = 1 << 2;
const RSN_CAP_PTKSA_REPLAY_COUNT_4: u16 = 1 << 3;
const RSN_CAP_GTKSA_REPLAY_COUNT_2: u16 = 1 << 4;
const RSN_CAP_GTKSA_REPLAY_COUNT_4: u16 = 1 << 5;
const RSN_CAP_MFPR: u16 = 1 << 6;
const RSN_CAP_MFPC: u16 = 1 << 7;
const RSN_CAP_JOINT_MULTI_BAND_RSNA: u16 = 1 << 8;
const RSN_CAP_PEER_KEY_ENABLED: u16 = 1 << 9;
const RSN_CAP_BIP_COMPACT_ENCAPSULATION: u16 = 1 << 12;
const RSN_CAP_EXTENDED_KEY_ID_PTKSA: u16 = 1 << 13;
const RSN_CAP_OCVC: u16 = 1 << 14;

bitflags::bitflags! {
    /// If not bands are set, it means don't care and the device will decide
    /// what to use
    #[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
    #[non_exhaustive]
    pub struct Ieee80211RsnCapbilities: u16 {
        /// Indicates the AP support preauthentication.
        const PreAuth = RSN_CAP_PRE_AUTH;
        /// When Both PtksaReplayCount2 and PtksaReplayCount4 are set,
        /// it means 16 replay counters per PTKSA.
        /// When Neither PtksaReplayCount2 or PtksaReplayCount4 is set,
        /// it means 1 reply counter per PTKSA
        const PtksaReplayCount2 = RSN_CAP_PTKSA_REPLAY_COUNT_2;
        const PtksaReplayCount4 = RSN_CAP_PTKSA_REPLAY_COUNT_4;
        /// When Both GtksaReplayCount2 and GtksaReplayCount4 are set,
        /// it means 16 replay counters per GTKSA.
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
        /// BIP Compact Encapsulation (S1G).
        const BipCompactEncapsulation = RSN_CAP_BIP_COMPACT_ENCAPSULATION;
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

impl Ieee80211RsnCapbilities {
    pub const LENGTH: usize = 2;

    pub fn parse(raw: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self::from_bits_retain(parse_u16_le(raw).context(
            format!("Invalid Ieee80211RsnCapbilities payload {raw:?}"),
        )?))
    }
}

impl Emitable for Ieee80211RsnCapbilities {
    fn buffer_len(&self) -> usize {
        Self::LENGTH
    }

    fn emit(&self, buffer: &mut [u8]) {
        buffer.copy_from_slice(&self.bits().to_le_bytes())
    }
}

// Extended RSN Capabilities bit positions (within the field, where bits 0-3
// are the Field length subfield and bits 4+ are capabilities). Per IEEE Std
// 802.11-2024 Table 9-373 (Extended RSN Capabilities field). Bit 6 is
// allocated to the Wi-Fi Alliance (used for SAE-PK).
//
// The Field length subfield (n - 1) is 4 bits, so the field is at most 16
// octets (128 bits); the capabilities are therefore stored in a u128.
const RSNX_CAP_PROTECTED_TWT: u128 = 1 << 4;
const RSNX_CAP_SAE_H2E: u128 = 1 << 5;
const RSNX_CAP_SAE_PK: u128 = 1 << 6;
const RSNX_CAP_PROTECTED_WUR_FRAME: u128 = 1 << 7;
const RSNX_CAP_SECURE_LTF: u128 = 1 << 8;
const RSNX_CAP_SECURE_RTT: u128 = 1 << 9;
const RSNX_CAP_URNM_MFPR_X20: u128 = 1 << 10;
const RSNX_CAP_PROTECTED_ANNOUNCE: u128 = 1 << 11;
const RSNX_CAP_PBAC: u128 = 1 << 12;
const RSNX_CAP_EXTENDED_S1G_ACTION_PROTECTION: u128 = 1 << 13;
const RSNX_CAP_SPP_A_MSDU_CAPABLE: u128 = 1 << 14;
const RSNX_CAP_URNM_MFPR: u128 = 1 << 15;
const RSNX_CAP_SSID_PROTECTION: u128 = 1 << 21;
const RSNX_CAP_QMF_ACI_UNMASK: u128 = 1 << 22;

/// Maximum length of the Extended RSN Capabilities field in octets (the 4-bit
/// Field length subfield holds n - 1, so n is at most 16).
const RSNX_FIELD_MAX_OCTETS: usize = 16;

// Mask of the Field length subfield (low nibble of the first octet); not part
// of the capability bits.
const RSNX_FIELD_LEN_MASK: u128 = 0x0000_000F;

bitflags::bitflags! {
    /// Extended RSN Capabilities, carried in the RSNXE (RSN Extension
    /// element). Bits are defined in IEEE Std 802.11-2024 Table 9-373.
    ///
    /// A `u128` backing type is used because the Extended RSN Capabilities
    /// field is variable length: its first 4 bits are the Field length
    /// subfield holding `n - 1`, where `n` is the field length in octets. With
    /// a 4-bit subfield, `n` is at most 16 octets = 128 bits, so a `u128` can
    /// represent every possible capability bit (a `u32` could not).
    #[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
    #[non_exhaustive]
    pub struct Ieee80211RsnExtCapbilities: u128 {
        /// Protected TWT Operations Support (bit 4).
        const ProtectedTwt = RSNX_CAP_PROTECTED_TWT;
        /// SAE Hash-to-element (H2E) password derivation supported (bit 5).
        const SaeH2e = RSNX_CAP_SAE_H2E;
        /// SAE Public Key (SAE-PK) supported (bit 6, Wi-Fi Alliance).
        const SaePk = RSNX_CAP_SAE_PK;
        /// Protected WUR Frame Support (bit 7).
        const ProtectedWurFrame = RSNX_CAP_PROTECTED_WUR_FRAME;
        /// Secure HE-LTF Support (bit 8).
        const SecureLtf = RSNX_CAP_SECURE_LTF;
        /// Secure RTT Support (bit 9).
        const SecureRtt = RSNX_CAP_SECURE_RTT;
        /// URNM-MFPR-X20 (bit 10): unassociated range negotiation/measurement,
        /// management frame protection required (dot11RSTARequiresPMF = 1).
        const UrnmMfprX20 = RSNX_CAP_URNM_MFPR_X20;
        /// Protected Announce Support (bit 11).
        const ProtectedAnnounce = RSNX_CAP_PROTECTED_ANNOUNCE;
        /// Protected Block Ack Agreement Capable (PBAC) (bit 12).
        const Pbac = RSNX_CAP_PBAC;
        /// Extended S1G Action Protection (bit 13).
        const ExtendedS1gActionProtection =
            RSNX_CAP_EXTENDED_S1G_ACTION_PROTECTION;
        /// SPP A-MSDU Capable (bit 14).
        const SppAMsduCapable = RSNX_CAP_SPP_A_MSDU_CAPABLE;
        /// URNM-MFPR (bit 15): unassociated range negotiation/measurement,
        /// management frame protection required (dot11RSTARequiresPMF = 2).
        const UrnmMfpr = RSNX_CAP_URNM_MFPR;
        /// SSID Protection in the 4-way handshake supported (bit 21).
        const SsidProtection = RSNX_CAP_SSID_PROTECTION;
        /// QMF ACI Subfield Unmask Support (bit 22).
        const QmfAciUnmask = RSNX_CAP_QMF_ACI_UNMASK;
        const _ = !0;
    }
}

/// RSN Extension element (RSNXE), IEEE 802.11 element id 244.
///
/// Carries the Extended RSN Capabilities; for WPA3 the most relevant bit is
/// [`Ieee80211RsnExtCapbilities::SaeH2e`]. The Field length subfield in the low
/// nibble of the first octet is computed automatically from the capability
/// bits and need not be set by the caller.
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub struct Ieee80211ElementRsnExt {
    pub capabilities: Ieee80211RsnExtCapbilities,
}

impl Ieee80211ElementRsnExt {
    /// Number of octets of the Extended RSN Capabilities field needed to hold
    /// the set capability bits (at least 1, at most [`RSNX_FIELD_MAX_OCTETS`]).
    fn octet_len(&self) -> usize {
        let caps = self.capabilities.bits() & !RSNX_FIELD_LEN_MASK;
        if caps == 0 {
            1
        } else {
            ((127 - caps.leading_zeros()) as usize / 8 + 1)
                .min(RSNX_FIELD_MAX_OCTETS)
        }
    }

    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        if payload.is_empty() {
            return Err(format!(
                "Invalid Ieee80211ElementRsnExt payload {payload:?}"
            )
            .into());
        }
        // The authoritative field length is the Field length subfield (low 4
        // bits of the first octet) plus 1, capped at the 16-octet maximum.
        // Trust it over the slice length so trailing padding / extra bytes are
        // not misparsed as higher-order capability bits.
        let n = ((payload[0] & RSNX_FIELD_LEN_MASK as u8) as usize + 1)
            .min(RSNX_FIELD_MAX_OCTETS);
        let len = payload.len().min(n);
        let mut raw = [0u8; RSNX_FIELD_MAX_OCTETS];
        raw[..len].copy_from_slice(&payload[..len]);
        // Drop the Field length subfield (low nibble); keep the capabilities.
        let bits = u128::from_le_bytes(raw) & !RSNX_FIELD_LEN_MASK;
        Ok(Self {
            capabilities: Ieee80211RsnExtCapbilities::from_bits_retain(bits),
        })
    }
}

impl Emitable for Ieee80211ElementRsnExt {
    fn buffer_len(&self) -> usize {
        self.octet_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        let octets = self.octet_len();
        let caps = self.capabilities.bits() & !RSNX_FIELD_LEN_MASK;
        let field = caps | ((octets as u128 - 1) & RSNX_FIELD_LEN_MASK);
        buffer[..octets].copy_from_slice(&field.to_le_bytes()[..octets]);
    }
}

/// Authentication Key Management Suite
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Ieee80211Pmkid(pub [u8; 16]);

impl Ieee80211Pmkid {
    pub const LENGTH: usize = 16;

    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        if payload.len() < Self::LENGTH {
            Err(format!(
                "Invalid buffer length for Ieee80211Pmkid, \
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

    pub fn emit(&self, buffer: &mut [u8]) {
        buffer[..Self::LENGTH].copy_from_slice(&self.0);
    }
}

/// Extended Capabilities bit 19: the BSS Transition capability
/// (IEEE 802.11-2020 11.21.7, Table 9-192). Set by an AP that
/// participates in BSS Transition Management.
const EXT_CAP_BSS_TRANSITION: usize = 19;
/// RM Enabled Capabilities octet 0 bit 1: the Neighbor Report capability
/// (IEEE 802.11-2020 11.10.10). Set by an AP that answers neighbor
/// report requests.
const RM_CAP_NEIGHBOR_REPORT: u8 = 1 << 1;

/// Find an element in an information element buffer and return the
/// offset of its Element ID octet.
///
/// The `ies` buffer holds concatenated elements, each
/// `Element ID (1) || Length (1) || body (Length)` (IEEE 802.11-2024
/// Figure 9-208). Malformed trailing data ends the search.
pub fn find_ie_pos(ies: &[u8], id: u8) -> Option<usize> {
    let mut pos = 0;
    while let Ok((header, _)) = Ieee80211ElementBuffer::split(&ies[pos..]) {
        if header.element_id == id {
            return Some(pos);
        }
        pos += header.buffer_len();
    }
    None
}

/// Find an element in an information element buffer and return its
/// body, without the Element ID/Length header.
pub fn find_ie(ies: &[u8], id: u8) -> Option<&[u8]> {
    let pos = find_ie_pos(ies, id)?;
    let (_, body) = Ieee80211ElementBuffer::split(&ies[pos..]).ok()?;
    Some(body)
}

/// The full element (`Element ID || Length || body`) starting at `pos`, as
/// returned by [`find_ie_pos`].
///
/// # Panics
///
/// Panics when `pos` does not hold a complete element; a position returned
/// by [`find_ie_pos`] always does.
pub fn ie_at(ies: &[u8], pos: usize) -> &[u8] {
    let (header, _) = Ieee80211ElementBuffer::split(&ies[pos..])
        .expect("ie_at() position does not hold a complete element");
    &ies[pos..pos + header.buffer_len()]
}

/// Whether the AP's information elements advertise the BSS Transition
/// (IEEE 802.11v) capability: bit 19 of the Extended Capabilities
/// element (IEEE 802.11-2020 9.4.2.26). A missing or too-short element
/// is not a BTM AP.
pub fn ap_supports_btm(ies: &[u8]) -> bool {
    find_ie(ies, ELEMENT_ID_EXT_CAPAB).is_some_and(|body| {
        body.get(EXT_CAP_BSS_TRANSITION / 8).is_some_and(|octet| {
            octet & (1 << (EXT_CAP_BSS_TRANSITION % 8)) != 0
        })
    })
}

/// Whether the AP's information elements advertise the Neighbor Report
/// (IEEE 802.11k) capability: bit 1 of octet 0 of the RM Enabled
/// Capabilities element (IEEE 802.11-2020 9.4.2.43). A missing or
/// malformed element is not a neighbor-report AP.
pub fn ap_supports_rm_neighbor_report(ies: &[u8]) -> bool {
    find_ie(ies, ELEMENT_ID_RM_ENABLED_CAPAB).is_some_and(|body| {
        body.first()
            .is_some_and(|octet| octet & RM_CAP_NEIGHBOR_REPORT != 0)
    })
}

/// Parse an RSNE body (the part after the Element ID and Length octets)
/// into the typed RSN model.
fn parse_rsne_body(body: &[u8]) -> Option<Ieee80211ElementRsn> {
    Ieee80211ElementRsn::parse(body).ok()
}

/// First PMKID of an RSNE body (after the element header), if the RSNE
/// carries one.
pub fn rsne_first_pmkid(body: &[u8]) -> Option<[u8; 16]> {
    parse_rsne_body(body)?.pmkids.first().map(|pmkid| pmkid.0)
}

/// The group management (BIP) cipher the AP advertises in its RSNE
/// (full element: Element ID || Length || body); `None` when absent
/// (older PMF-optional RSNEs omit it, and BIP-CMAC-128 is then
/// assumed).
pub fn parse_group_mgmt_cipher(rsne: &[u8]) -> Option<Ieee80211CipherSuite> {
    let (_, body) = Ieee80211ElementBuffer::split(rsne).ok()?;
    parse_rsne_body(body)?.group_mgmt_cipher
}

/// Whether the AP's RSNXE (full element: Element ID || Length || body, as
/// delivered in beacons and probe responses) advertises SAE
/// Hash-to-Element support. An empty slice (no RSNXE) or an element
/// that does not hold the complete body its Length field promises both
/// mean "not advertised".
pub fn ap_rsnxe_supports_sae_h2e(ap_rsnxe: &[u8]) -> bool {
    let Ok((_, body)) = Ieee80211ElementBuffer::split(ap_rsnxe) else {
        return false;
    };
    Ieee80211ElementRsnExt::parse(body).is_ok_and(|rsnxe| {
        rsnxe
            .capabilities
            .contains(Ieee80211RsnExtCapbilities::SaeH2e)
    })
}

/// Offset of the RSN capabilities field (2 octets) inside an RSNE
/// (full element: Element ID || Length || body).
///
/// The offset is derived from the pairwise cipher and AKM suite
/// counts; the element body the Length field promises bounds the
/// search, so an RSNE followed by other elements - the RSNXE of an SAE
/// association request, for instance - is handled as well.
fn rsne_capabilities_offset(rsne: &[u8]) -> Option<usize> {
    let (_, body) = Ieee80211ElementBuffer::split(rsne).ok()?;
    // version(2) group(4) pcount(2) pciphers acount(2) akms capab(2)
    if body.len() < 8 {
        return None;
    }
    let pcount = u16::from_le_bytes([body[6], body[7]]) as usize;
    let akm_off = 8 + pcount * 4;
    if body.len() < akm_off + 2 {
        return None;
    }
    let acount =
        u16::from_le_bytes([body[akm_off], body[akm_off + 1]]) as usize;
    let capab_off = akm_off + 2 + acount * 4;
    body.get(capab_off..capab_off + 2)?;
    // The body starts after the Element ID and Length octets.
    Some(capab_off + Ieee80211ElementBuffer::LEN)
}

/// Whether an RSNE advertises the given RSN capability (IEEE
/// 802.11-2024 9.4.2.23). A missing or malformed element, or one
/// without the RSN capabilities field, means "not advertised".
fn rsne_has_capability(
    rsne: &[u8],
    capability: Ieee80211RsnCapbilities,
) -> bool {
    let Some(offset) = rsne_capabilities_offset(rsne) else {
        return false;
    };
    let capab = u16::from_le_bytes([rsne[offset], rsne[offset + 1]]);
    Ieee80211RsnCapbilities::from_bits_truncate(capab).contains(capability)
}

/// Whether the AP's RSNE (full element: ID || length || body)
/// advertises the OCVC RSN capability (bit 14, IEEE 802.11-2020
/// 9.4.2.25): Operating Channel Validation is only meaningful against
/// an AP that advertises it, an AP that does not will never include an
/// OCI KDE in the 4-way handshake Message 3.
pub fn ap_rsne_supports_ocv(ap_rsne: &[u8]) -> bool {
    rsne_has_capability(ap_rsne, Ieee80211RsnCapbilities::Ocvc)
}

/// Whether the AP's RSNE advertises the Extended Key ID for
/// Individually Addressed Frames RSN capability (bit 13, IEEE
/// 802.11-2020 9.4.2.25): an AP that does not will never send a Key ID
/// KDE in the 4-way handshake Message 3.
pub fn ap_rsne_supports_ext_key_id(ap_rsne: &[u8]) -> bool {
    rsne_has_capability(ap_rsne, Ieee80211RsnCapbilities::ExtendedKeyIdPtksa)
}

/// Set or clear an RSN capability in an RSNE: only the 2 capability
/// octets are rewritten, so whatever follows the RSNE - the RSNXE of
/// an SAE association request, for instance - is left untouched. A
/// malformed element, or one without the RSN capabilities field, is
/// left untouched.
fn rsne_set_capability(
    rsne: &mut [u8],
    capability: Ieee80211RsnCapbilities,
    enabled: bool,
) {
    let Some(offset) = rsne_capabilities_offset(rsne) else {
        return;
    };
    let capab = u16::from_le_bytes([rsne[offset], rsne[offset + 1]]);
    let capab = if enabled {
        capab | capability.bits()
    } else {
        capab & !capability.bits()
    };
    rsne[offset..offset + 2].copy_from_slice(&capab.to_le_bytes());
}

/// Set or clear the OCV capability bit (bit 14) in the RSN
/// capabilities of an RSNE element.
pub fn rsne_set_ocvc(rsne: &mut [u8], enabled: bool) {
    rsne_set_capability(rsne, Ieee80211RsnCapbilities::Ocvc, enabled);
}

/// Set or clear the Extended Key ID capability bit (bit 13) in the RSN
/// capabilities of an RSNE element.
pub fn rsne_set_ext_key_id(rsne: &mut [u8], enabled: bool) {
    rsne_set_capability(
        rsne,
        Ieee80211RsnCapbilities::ExtendedKeyIdPtksa,
        enabled,
    );
}

/// The RSNXE element advertising SAE Hash-to-Element support, as an
/// element buffer (ID + length + body).
pub fn sae_rsnxe() -> Vec<u8> {
    let elements = Ieee80211Elements(vec![Ieee80211Element::RsnExt(
        Ieee80211ElementRsnExt {
            capabilities: Ieee80211RsnExtCapbilities::SaeH2e,
        },
    )]);

    let mut buf = vec![0u8; elements.buffer_len()];
    elements.emit(&mut buf);
    buf
}

/// Build the RSNE + RSNXE for WPA3-Personal (SAE, CCMP-128, management
/// frame protection required, SAE Hash-to-Element) with the negotiated
/// group management (BIP) cipher.
///
/// The exact same bytes are used in the Association Request and in the
/// 4-way handshake Message 2, so both call sites must use this single
/// builder.
pub fn sae_ie_cipher(mgmt_cipher: Ieee80211CipherSuite) -> Vec<u8> {
    sae_ie_with_pmkid_cipher(None, mgmt_cipher)
}

/// [`sae_ie_cipher`] carrying a PMKID.
pub fn sae_ie_with_pmkid_cipher(
    pmkid: Option<[u8; 16]>,
    mgmt_cipher: Ieee80211CipherSuite,
) -> Vec<u8> {
    let elements = Ieee80211Elements(vec![
        Ieee80211Element::Rsn(Ieee80211ElementRsn {
            version: 1,
            group_cipher: Some(Ieee80211CipherSuite::Ccmp128),
            pairwise_ciphers: vec![Ieee80211CipherSuite::Ccmp128],
            akm_suits: vec![Ieee80211AkmSuite::Sae],
            rsn_capbilities: Some(
                Ieee80211RsnCapbilities::Mfpr | Ieee80211RsnCapbilities::Mfpc,
            ),
            pmkids: pmkid.into_iter().map(Ieee80211Pmkid).collect(),
            group_mgmt_cipher: Some(mgmt_cipher),
        }),
        Ieee80211Element::RsnExt(Ieee80211ElementRsnExt {
            capabilities: Ieee80211RsnExtCapbilities::SaeH2e,
        }),
    ]);

    let mut buf = vec![0u8; elements.buffer_len()];
    elements.emit(&mut buf);
    buf
}

/// Build the RSNE + RSNXE for SAE-EXT-KEY (AKM 00-0F-AC:24): same
/// security policy as [`sae_ie_cipher`], only the AKM differs.
pub fn sae_ext_key_ie_cipher(mgmt_cipher: Ieee80211CipherSuite) -> Vec<u8> {
    sae_ext_key_ie_with_pmkid_cipher(None, mgmt_cipher)
}

/// [`sae_ext_key_ie_cipher`] carrying a PMKID.
pub fn sae_ext_key_ie_with_pmkid_cipher(
    pmkid: Option<[u8; 16]>,
    mgmt_cipher: Ieee80211CipherSuite,
) -> Vec<u8> {
    let elements = Ieee80211Elements(vec![
        Ieee80211Element::Rsn(Ieee80211ElementRsn {
            version: 1,
            group_cipher: Some(Ieee80211CipherSuite::Ccmp128),
            pairwise_ciphers: vec![Ieee80211CipherSuite::Ccmp128],
            akm_suits: vec![Ieee80211AkmSuite::SaeGroupDependentHash],
            rsn_capbilities: Some(
                Ieee80211RsnCapbilities::Mfpr | Ieee80211RsnCapbilities::Mfpc,
            ),
            pmkids: pmkid.into_iter().map(Ieee80211Pmkid).collect(),
            group_mgmt_cipher: Some(mgmt_cipher),
        }),
        Ieee80211Element::RsnExt(Ieee80211ElementRsnExt {
            capabilities: Ieee80211RsnExtCapbilities::SaeH2e,
        }),
    ]);

    let mut buf = vec![0u8; elements.buffer_len()];
    elements.emit(&mut buf);
    buf
}

/// Build the FT-SAE-EXT-KEY RSNE element only (AKM 00-0F-AC:25).
pub fn ft_sae_ext_key_rsne_cipher(
    pmkid: Option<[u8; 16]>,
    mgmt_cipher: Ieee80211CipherSuite,
) -> Vec<u8> {
    let elements =
        Ieee80211Elements(vec![Ieee80211Element::Rsn(Ieee80211ElementRsn {
            version: 1,
            group_cipher: Some(Ieee80211CipherSuite::Ccmp128),
            pairwise_ciphers: vec![Ieee80211CipherSuite::Ccmp128],
            akm_suits: vec![Ieee80211AkmSuite::FtSaeGroupDependentHash],
            rsn_capbilities: Some(
                Ieee80211RsnCapbilities::Mfpr | Ieee80211RsnCapbilities::Mfpc,
            ),
            pmkids: pmkid.into_iter().map(Ieee80211Pmkid).collect(),
            group_mgmt_cipher: Some(mgmt_cipher),
        })]);

    let mut buf = vec![0u8; elements.buffer_len()];
    elements.emit(&mut buf);
    buf
}

/// Build the RSNE + RSNXE for FT-SAE-EXT-KEY (AKM 00-0F-AC:25).
pub fn ft_sae_ext_key_ie_cipher(
    pmkid: Option<[u8; 16]>,
    mgmt_cipher: Ieee80211CipherSuite,
) -> Vec<u8> {
    let mut buf = ft_sae_ext_key_rsne_cipher(pmkid, mgmt_cipher);
    buf.extend_from_slice(&sae_rsnxe());
    buf
}

/// Build the RSNE for OWE (AKM 00-0F-AC:18, CCMP-128, MFP required).
/// No RSNXE: OWE does not use SAE Hash-to-Element.
pub fn owe_ie_cipher(mgmt_cipher: Ieee80211CipherSuite) -> Vec<u8> {
    let elements =
        Ieee80211Elements(vec![Ieee80211Element::Rsn(Ieee80211ElementRsn {
            version: 1,
            group_cipher: Some(Ieee80211CipherSuite::Ccmp128),
            pairwise_ciphers: vec![Ieee80211CipherSuite::Ccmp128],
            akm_suits: vec![Ieee80211AkmSuite::Owe],
            rsn_capbilities: Some(
                Ieee80211RsnCapbilities::Mfpr | Ieee80211RsnCapbilities::Mfpc,
            ),
            pmkids: vec![],
            group_mgmt_cipher: Some(mgmt_cipher),
        })]);

    let mut buf = vec![0u8; elements.buffer_len()];
    elements.emit(&mut buf);
    buf
}

/// Build the RSNE for WPA2-PSK (AKM 00-0F-AC:2, CCMP-128) with
/// optional management frame protection (MFPC without MFPR, iwd's
/// default `ManagementFrameProtection=1` behaviour).
pub fn wpa2_psk_ie_cipher(mgmt_cipher: Ieee80211CipherSuite) -> Vec<u8> {
    wpa2_psk_ie_with_pmkid_cipher(None, mgmt_cipher)
}

/// [`wpa2_psk_ie_cipher`] carrying a PMKID.
pub fn wpa2_psk_ie_with_pmkid_cipher(
    pmkid: Option<[u8; 16]>,
    mgmt_cipher: Ieee80211CipherSuite,
) -> Vec<u8> {
    let elements =
        Ieee80211Elements(vec![Ieee80211Element::Rsn(Ieee80211ElementRsn {
            version: 1,
            group_cipher: Some(Ieee80211CipherSuite::Ccmp128),
            pairwise_ciphers: vec![Ieee80211CipherSuite::Ccmp128],
            akm_suits: vec![Ieee80211AkmSuite::Psk],
            rsn_capbilities: Some(Ieee80211RsnCapbilities::Mfpc),
            pmkids: pmkid.into_iter().map(Ieee80211Pmkid).collect(),
            group_mgmt_cipher: Some(mgmt_cipher),
        })]);

    let mut buf = vec![0u8; elements.buffer_len()];
    elements.emit(&mut buf);
    buf
}

/// Build the RSNE for WPA2-Personal with SHA-256 algorithms
/// (PSK-SHA256, AKM 00-0F-AC:6, CCMP-128): same security policy as
/// [`wpa2_psk_ie_cipher`], only the AKM suite differs.
pub fn wpa2_psk_sha256_ie_cipher(mgmt_cipher: Ieee80211CipherSuite) -> Vec<u8> {
    wpa2_psk_sha256_ie_with_pmkid_cipher(None, mgmt_cipher)
}

/// [`wpa2_psk_sha256_ie_cipher`] carrying a PMKID.
pub fn wpa2_psk_sha256_ie_with_pmkid_cipher(
    pmkid: Option<[u8; 16]>,
    mgmt_cipher: Ieee80211CipherSuite,
) -> Vec<u8> {
    let elements =
        Ieee80211Elements(vec![Ieee80211Element::Rsn(Ieee80211ElementRsn {
            version: 1,
            group_cipher: Some(Ieee80211CipherSuite::Ccmp128),
            pairwise_ciphers: vec![Ieee80211CipherSuite::Ccmp128],
            akm_suits: vec![Ieee80211AkmSuite::PskSha256],
            rsn_capbilities: Some(Ieee80211RsnCapbilities::Mfpc),
            pmkids: pmkid.into_iter().map(Ieee80211Pmkid).collect(),
            group_mgmt_cipher: Some(mgmt_cipher),
        })]);

    let mut buf = vec![0u8; elements.buffer_len()];
    elements.emit(&mut buf);
    buf
}

/// Build the RSNE for WPA2-Enterprise (802.1X, AKM 00-0F-AC:1,
/// CCMP-128) with optional management frame protection.
pub fn wpa2_ent_ie_cipher(mgmt_cipher: Ieee80211CipherSuite) -> Vec<u8> {
    let elements =
        Ieee80211Elements(vec![Ieee80211Element::Rsn(Ieee80211ElementRsn {
            version: 1,
            group_cipher: Some(Ieee80211CipherSuite::Ccmp128),
            pairwise_ciphers: vec![Ieee80211CipherSuite::Ccmp128],
            akm_suits: vec![Ieee80211AkmSuite::Ieee8021x],
            rsn_capbilities: Some(Ieee80211RsnCapbilities::Mfpc),
            pmkids: vec![],
            group_mgmt_cipher: Some(mgmt_cipher),
        })]);

    let mut buf = vec![0u8; elements.buffer_len()];
    elements.emit(&mut buf);
    buf
}

/// Build the RSNE for WPA3-Enterprise (802.1X-SHA256, AKM
/// 00-0F-AC:5, CCMP-128) with **mandatory** management frame
/// protection (MFPR + MFPC), the WPA3 baseline requirement.
pub fn wpa2_ent_sha256_ie_cipher(mgmt_cipher: Ieee80211CipherSuite) -> Vec<u8> {
    let elements =
        Ieee80211Elements(vec![Ieee80211Element::Rsn(Ieee80211ElementRsn {
            version: 1,
            group_cipher: Some(Ieee80211CipherSuite::Ccmp128),
            pairwise_ciphers: vec![Ieee80211CipherSuite::Ccmp128],
            akm_suits: vec![Ieee80211AkmSuite::Ieee8021xSha256],
            rsn_capbilities: Some(
                Ieee80211RsnCapbilities::Mfpr | Ieee80211RsnCapbilities::Mfpc,
            ),
            pmkids: vec![],
            group_mgmt_cipher: Some(mgmt_cipher),
        })]);

    let mut buf = vec![0u8; elements.buffer_len()];
    elements.emit(&mut buf);
    buf
}

/// Build the FT-SAE RSNE element only (AKM 00-0F-AC:9). Used where the
/// RSNE and RSNXE must stay separate elements (FT Reassociation
/// Request: the FTIE MIC covers RSNE, MDIE, FTIE, then RSNXE in that
/// order).
pub fn ft_sae_rsne_cipher(
    pmkid: Option<[u8; 16]>,
    mgmt_cipher: Ieee80211CipherSuite,
) -> Vec<u8> {
    let elements =
        Ieee80211Elements(vec![Ieee80211Element::Rsn(Ieee80211ElementRsn {
            version: 1,
            group_cipher: Some(Ieee80211CipherSuite::Ccmp128),
            pairwise_ciphers: vec![Ieee80211CipherSuite::Ccmp128],
            akm_suits: vec![Ieee80211AkmSuite::FtSae],
            rsn_capbilities: Some(
                Ieee80211RsnCapbilities::Mfpr | Ieee80211RsnCapbilities::Mfpc,
            ),
            pmkids: pmkid.into_iter().map(Ieee80211Pmkid).collect(),
            group_mgmt_cipher: Some(mgmt_cipher),
        })]);

    let mut buf = vec![0u8; elements.buffer_len()];
    elements.emit(&mut buf);
    buf
}

/// Build the FT-PSK RSNE element only (AKM 00-0F-AC:4); see
/// [`ft_sae_rsne_cipher`].
pub fn ft_psk_rsne_cipher(
    pmkid: Option<[u8; 16]>,
    mgmt_cipher: Ieee80211CipherSuite,
) -> Vec<u8> {
    let elements =
        Ieee80211Elements(vec![Ieee80211Element::Rsn(Ieee80211ElementRsn {
            version: 1,
            group_cipher: Some(Ieee80211CipherSuite::Ccmp128),
            pairwise_ciphers: vec![Ieee80211CipherSuite::Ccmp128],
            akm_suits: vec![Ieee80211AkmSuite::FtPsk],
            rsn_capbilities: Some(Ieee80211RsnCapbilities::Mfpc),
            pmkids: pmkid.into_iter().map(Ieee80211Pmkid).collect(),
            group_mgmt_cipher: Some(mgmt_cipher),
        })]);

    let mut buf = vec![0u8; elements.buffer_len()];
    elements.emit(&mut buf);
    buf
}

/// Build the RSNE + RSNXE for FT-SAE (AKM 00-0F-AC:9): same crypto
/// policy as [`sae_ie_cipher`], only the AKM differs. `pmkid` carries
/// PMKR0Name / PMKR1Name during FT.
pub fn ft_sae_ie_cipher(
    pmkid: Option<[u8; 16]>,
    mgmt_cipher: Ieee80211CipherSuite,
) -> Vec<u8> {
    let mut buf = ft_sae_rsne_cipher(pmkid, mgmt_cipher);
    buf.extend_from_slice(&sae_rsnxe());
    buf
}

/// Build the RSNE for FT-PSK (AKM 00-0F-AC:4): same crypto policy as
/// [`wpa2_psk_ie_cipher`]. `pmkid` carries PMKR0Name / PMKR1Name
/// during FT.
pub fn ft_psk_ie_cipher(
    pmkid: Option<[u8; 16]>,
    mgmt_cipher: Ieee80211CipherSuite,
) -> Vec<u8> {
    ft_psk_rsne_cipher(pmkid, mgmt_cipher)
}

/// Build a Mobility Domain element: MDID (2) || FT Capability and
/// Policy (1). `ft_capab` is normally echoed from the target AP's MDIE.
pub fn mdie(mdid: [u8; 2], ft_capab: u8) -> Vec<u8> {
    vec![ELEMENT_ID_MDIE, 3, mdid[0], mdid[1], ft_capab]
}

/// Parse a Mobility Domain element body: (MDID, FT capability/policy).
pub fn parse_mdie(body: &[u8]) -> Option<([u8; 2], u8)> {
    if body.len() < 3 {
        return None;
    }
    Some(([body[0], body[1]], body[2]))
}

/// FTIE subelement identifiers (IEEE 802.11-2020 9.4.2.48).
const FTIE_SUBELEM_R1KH_ID: u8 = 1;
const FTIE_SUBELEM_GTK: u8 = 2;
const FTIE_SUBELEM_R0KH_ID: u8 = 3;
const FTIE_SUBELEM_IGTK: u8 = 4;
const FTIE_SUBELEM_BIGTK: u8 = 6;

/// Build the FTIE of an over-the-air FT Authentication request
/// (transaction 1): SNonce and the R0KH-ID subelement, with the MIC
/// left zeroed. The first FT authentication frame carries no MIC
/// (wpa_supplicant's `wpa_ft_prepare_auth_request` does the same).
pub fn ftie_auth_request(snonce: &[u8; 32], r0kh_id: &[u8]) -> Vec<u8> {
    let body_len = 2 + 16 + 32 + 32 + 2 + r0kh_id.len();
    let mut e = Vec::with_capacity(2 + body_len);
    e.push(ELEMENT_ID_FTIE);
    e.push(body_len as u8);
    // MIC Control: MIC length code 0 (= 16 octets), element count 0.
    e.extend_from_slice(&[0, 0]);
    e.extend_from_slice(&[0u8; 16]); // MIC (zero)
    e.extend_from_slice(&[0u8; 32]); // ANonce (zero in the request)
    e.extend_from_slice(snonce);
    e.push(FTIE_SUBELEM_R0KH_ID);
    e.push(r0kh_id.len() as u8);
    e.extend_from_slice(r0kh_id);
    e
}

/// A group key delivered in an FTIE subelement (GTK / IGTK / BIGTK),
/// still AES-Key-Wrapped with the KEK.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Ieee80211FtKeySubelem {
    /// Key index: the GTK index (0-3) for a GTK subelement, the full
    /// key index (4-7) for IGTK / BIGTK.
    pub key_index: u8,
    /// Receive sequence counter: RSC (8 octets) for the GTK, IPN/BIPN
    /// (6 octets) for IGTK / BIGTK.
    pub rsc: Vec<u8>,
    /// The key, still AES-Key-Wrapped with the KEK.
    pub wrapped_key: Vec<u8>,
}

/// Parsed Fast BSS Transition element (IEEE 802.11-2020 9.4.2.48).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Ieee80211FtIe {
    /// MIC Control field: MIC length code and element count.
    pub mic_control: [u8; 2],
    /// MIC over the FT reassociation data.
    pub mic: [u8; 16],
    /// ANonce of the authenticator.
    pub anonce: [u8; 32],
    /// SNonce of the supplicant.
    pub snonce: [u8; 32],
    /// R0KH-ID subelement, when present.
    pub r0kh_id: Option<Vec<u8>>,
    /// R1KH-ID subelement, when present.
    pub r1kh_id: Option<[u8; 6]>,
    /// GTK subelement, when present.
    pub gtk: Option<Ieee80211FtKeySubelem>,
    /// IGTK subelement, when present.
    pub igtk: Option<Ieee80211FtKeySubelem>,
    /// BIGTK subelement, when present.
    pub bigtk: Option<Ieee80211FtKeySubelem>,
}

fn parse_ft_key_subelem(
    body: &[u8],
    rsc_len: usize,
) -> Option<Ieee80211FtKeySubelem> {
    if rsc_len == 8 {
        // GTK: Key Info[2] | Key Length[1] | RSC[8] | wrapped Key
        // (IEEE 802.11-2020 9.4.2.48.3); only the first 6 RSC octets
        // are the actual CCMP receive counter.
        if body.len() < 11 {
            return None;
        }
        let key_index = u16::from_le_bytes([body[0], body[1]]) & 0x03;
        Some(Ieee80211FtKeySubelem {
            key_index: key_index as u8,
            rsc: body[3..9].to_vec(),
            wrapped_key: body[11..].to_vec(),
        })
    } else {
        // IGTK / BIGTK: Key Info[2] | IPN[6] | Key Length[1] | wrapped
        // Key. Key Info carries the full key index (4-7), not a GTK
        // index masked to two bits.
        if body.len() < 9 {
            return None;
        }
        let key_index = u16::from_le_bytes([body[0], body[1]]) as u8;
        Some(Ieee80211FtKeySubelem {
            key_index,
            rsc: body[2..8].to_vec(),
            wrapped_key: body[9..].to_vec(),
        })
    }
}

/// Parse a Fast BSS Transition element body (after the IE header).
pub fn parse_ftie(body: &[u8]) -> Option<Ieee80211FtIe> {
    // Fixed part: MIC Control(2) || MIC(16) || ANonce(32) || SNonce(32).
    if body.len() < 2 + 16 + 32 + 32 {
        return None;
    }
    let mut ftie = Ieee80211FtIe {
        mic_control: [body[0], body[1]],
        mic: body[2..18].try_into().unwrap(),
        anonce: body[18..50].try_into().unwrap(),
        snonce: body[50..82].try_into().unwrap(),
        r0kh_id: None,
        r1kh_id: None,
        gtk: None,
        igtk: None,
        bigtk: None,
    };

    let mut pos = 82;
    while pos + 2 <= body.len() {
        let id = body[pos];
        let len = body[pos + 1] as usize;
        let start = pos + 2;
        let end = start + len;
        if end > body.len() {
            break;
        }
        let sub = &body[start..end];
        match id {
            FTIE_SUBELEM_R0KH_ID => ftie.r0kh_id = Some(sub.to_vec()),
            FTIE_SUBELEM_R1KH_ID if len == 6 => {
                ftie.r1kh_id = Some(sub.try_into().unwrap());
            }
            FTIE_SUBELEM_GTK => ftie.gtk = parse_ft_key_subelem(sub, 8),
            FTIE_SUBELEM_IGTK => ftie.igtk = parse_ft_key_subelem(sub, 6),
            FTIE_SUBELEM_BIGTK => ftie.bigtk = parse_ft_key_subelem(sub, 6),
            _ => {}
        }
        pos = end;
    }
    Some(ftie)
}

/// Compare two RSNE elements semantically while ignoring the PMKID
/// list: FT (Re)Association Responses carry PMKR0Name / PMKR1Name as
/// the PMKID, which the beacon RSNE lacks (wpa_supplicant's
/// `wpa_compare_rsn_ie` does the same for FT AKMs).
///
/// Each argument is either a full RSNE element or a bare RSNE body; the
/// comparison uses the typed RSN model, so octets after the modelled
/// fields are ignored. Inputs the typed parser rejects are compared
/// verbatim.
pub fn rsne_match_ignore_pmkid(a: &[u8], b: &[u8]) -> bool {
    let body_a = find_ie(a, ELEMENT_ID_RSN).unwrap_or(a);
    let body_b = find_ie(b, ELEMENT_ID_RSN).unwrap_or(b);
    match (parse_rsne_body(body_a), parse_rsne_body(body_b)) {
        (Some(mut rsn_a), Some(mut rsn_b)) => {
            rsn_a.pmkids.clear();
            rsn_b.pmkids.clear();
            rsn_a == rsn_b
        }
        _ => body_a == body_b,
    }
}
