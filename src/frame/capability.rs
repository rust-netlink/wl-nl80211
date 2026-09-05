// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    parse_u16, DecodeError, Emitable, ErrorContext, Parseable,
};

bitflags::bitflags! {
    /// IEEE 802.11-2024 §9.4.1.4, Figure 9-140: Capability Information
    /// field (non-DMG STA), carried by (Re)Association Response frames and
    /// Beacon/Probe Response frames.
    ///
    /// Only bits B0, B1, B4, B5 and B8-B13 are defined; bits B2, B3, B6,
    /// B7, B14 and B15 are reserved.
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    #[non_exhaustive]
    pub struct Ieee80211CapabilityInfo: u16 {
        const Ess = 1 << 0;
        const Ibss = 1 << 1;
        const Privacy = 1 << 4;
        const ShortPreamble = 1 << 5;
        const SpectrumManagement = 1 << 8;
        const Qos = 1 << 9;
        const ShortSlotTime = 1 << 10;
        const Apsd = 1 << 11;
        const RadioMeasurement = 1 << 12;
        const Epd = 1 << 13;
        const _ = !0;
    }
}

impl<T: AsRef<[u8]> + ?Sized> Parseable<T> for Ieee80211CapabilityInfo {
    fn parse(buf: &T) -> Result<Self, DecodeError> {
        let buf = buf.as_ref();
        Ok(Self::from_bits_retain(parse_u16(buf).context(format!(
            "Invalid Ieee80211CapabilityInfo payload {buf:?}"
        ))?))
    }
}

impl Ieee80211CapabilityInfo {
    pub const LENGTH: usize = 2;
}

impl Emitable for Ieee80211CapabilityInfo {
    fn buffer_len(&self) -> usize {
        Self::LENGTH
    }

    fn emit(&self, buffer: &mut [u8]) {
        buffer.copy_from_slice(&self.bits().to_ne_bytes())
    }
}
