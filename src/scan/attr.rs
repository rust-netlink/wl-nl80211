// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    parse_string, parse_u32, DecodeError, Emitable, ErrorContext, Nla,
    NlasIterator, Parseable,
};

use crate::bytes::write_u32;
#[cfg(doc)]
use crate::Nl80211Attr;

#[derive(Debug, Clone)]
pub(crate) struct Nla80211ScanSsidNla {
    index: u16,
    ssid: String,
}

impl Nla for Nla80211ScanSsidNla {
    fn value_len(&self) -> usize {
        self.ssid.len()
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        buffer.copy_from_slice(self.ssid.as_bytes())
    }

    fn kind(&self) -> u16 {
        // Linux kernel has no check on this value, but iw `scan.c`
        // index start from 1.
        self.index + 1
    }
}

pub(crate) struct Nla80211ScanSsidNlas(Vec<Nla80211ScanSsidNla>);

impl std::ops::Deref for Nla80211ScanSsidNlas {
    type Target = Vec<Nla80211ScanSsidNla>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<&Vec<String>> for Nla80211ScanSsidNlas {
    fn from(ssids: &Vec<String>) -> Self {
        let mut nlas = Vec::new();
        for (i, ssid) in ssids.iter().enumerate() {
            let nla = Nla80211ScanSsidNla {
                index: i as u16,
                ssid: ssid.to_string(),
            };
            nlas.push(nla);
        }
        Nla80211ScanSsidNlas(nlas)
    }
}

impl From<Nla80211ScanSsidNlas> for Vec<String> {
    fn from(ssids: Nla80211ScanSsidNlas) -> Self {
        let mut ssids = ssids;
        ssids.0.drain(..).map(|c| c.ssid).collect()
    }
}

impl Nla80211ScanSsidNlas {
    pub(crate) fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let mut ssids: Vec<Nla80211ScanSsidNla> = Vec::new();
        for (index, nla) in NlasIterator::new(payload).enumerate() {
            let error_msg = format!("Invalid NL80211_ATTR_SCAN_SSIDS: {nla:?}");
            let nla = &nla.context(error_msg.clone())?;
            let ssid = parse_string(nla.value())
                .context(format!("Invalid NL80211_ATTR_SCAN_SSIDS: {nla:?}"))?;
            ssids.push(Nla80211ScanSsidNla {
                index: index as u16,
                ssid,
            });
        }
        Ok(Self(ssids))
    }
}

bitflags::bitflags! {
    /// Scan request control flags
    // Kernel data type: enum nl80211_scan_flags
    #[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
    #[non_exhaustive]
    pub struct Nl80211ScanFlags: u32 {
        /// Scan request has low priority
        const LowPriority = 1 << 0;
        /// Flush cache before scanning
        const Flush = 1 << 1;
        /// Force a scan even if the interface is configured as AP and the
        /// beaconing has already been configured. This attribute is dangerous
        /// because will destroy stations performance as a lot of frames will be
        /// lost while scanning off-channel, therefore it must be used only when
        /// really needed
        const Ap = 1 << 2;
        /// Use a random MAC address for this scan (or for scheduled scan: a
        /// different one for every scan iteration). When the flag is set,
        /// depending on device capabilities the [Nl80211Attr::Mac] and
        /// [Nl80211Attr::MacMask] attributes may also be given in which case
        /// only the masked bits will be preserved from the MAC address and the
        /// remainder randomised. If the attributes are not given full
        /// randomisation (46 bits, locally administered 1, multicast 0) is
        /// assumed.  This flag must not be requested when the feature isn't
        /// supported, check the [Nl80211Attr::Features] for the device.
        const RandomAddr = 1 << 3;
        /// Fill the dwell time in the FILS request parameters IE in the probe
        /// request
        const FilsMaxChannelTime = 1 << 4;
        /// Accept broadcast probe responses
        const AcceptBcastProbeResp = 1 << 5;
        /// Send probe request frames at rate of at least 5.5M. In case non-OCE
        /// AP is discovered in the channel, only the first probe req in the
        /// channel will be sent in high rate.
        const OceProbeReqHighTxRate = 1 << 6;
        /// Allow probe request tx deferral (dot11FILSProbeDelay shall be set to
        /// 15ms) and suppression (if it has received a broadcast Probe Response
        /// frame, Beacon frame or FILS Discovery frame from an AP that the STA
        /// considers a suitable candidate for (re-)association - suitable in
        /// terms of SSID and/or RSSI.
        const OceProbeReqDeferralSuppression = 1 << 7;
        /// Span corresponds to the total time taken to accomplish the scan.
        /// Thus, this flag intends the driver to perform the scan request with
        /// lesser span/duration. It is specific to the driver implementations
        /// on how this is accomplished. Scan accuracy may get impacted with
        /// this flag.
        const LowSpan = 1 << 8;
        /// This flag intends the scan attempts to consume optimal possible
        /// power. Drivers can resort to their specific means to optimize the
        /// power. Scan accuracy may get impacted with this flag.
        const LowPower = 1 << 9;
        /// Accuracy here intends to the extent of scan results obtained. Thus
        /// HIGH_ACCURACY scan flag aims to get maximum possible scan results.
        /// This flag hints the driver to use the best possible scan
        /// configuration to improve the accuracy in scanning.  Latency and
        /// power use may get impacted with this flag.
        const HighAccuracy = 1 << 10;
        /// Randomize the sequence number in probe request frames from this
        /// scan to avoid correlation/tracking being possible.
        const RandomSn = 1 << 11;
        /// Minimize probe request content to only have supported rates and no
        /// additional capabilities (unless added by userspace explicitly.)
        const MinPreqContent = 1 << 12;
        /// Report scan results with [Nl80211Attr::ScanFreqKhz].
        /// This also means [Nl80211Attr::ScanFreq] will not be included.
        const FreqKhz = 1 << 13;
        /// Scan for collocated APs reported by 2.4/5 GHz APs. When the flag is
        /// set, the scan logic will use the information from the RNR element
        /// found in beacons/probe responses received on the 2.4/5 GHz channels
        /// to actively scan only the 6GHz channels on which APs are expected to
        /// be found. Note that when not set, the scan logic would scan all 6GHz
        /// channels, but since transmission of probe requests on non-PSC
        /// channels is limited, it is highly likely that these channels would
        /// passively be scanned. Also note that when the flag is set, in
        /// addition to the colocated APs, PSC channels would also be scanned if
        /// the user space has asked for it.
        const Colocated6Ghz = 1 << 14;
        const _ = !0;
    }
}

impl<T: AsRef<[u8]> + ?Sized> Parseable<T> for Nl80211ScanFlags {
    fn parse(buf: &T) -> Result<Self, DecodeError> {
        let buf: &[u8] = buf.as_ref();
        Ok(Self::from_bits_retain(parse_u32(buf).context(format!(
            "Invalid Nl80211ScanFlags payload {buf:?}"
        ))?))
    }
}

impl Nl80211ScanFlags {
    pub const LENGTH: usize = 4;
}

impl Emitable for Nl80211ScanFlags {
    fn buffer_len(&self) -> usize {
        Self::LENGTH
    }

    fn emit(&self, buffer: &mut [u8]) {
        buffer.copy_from_slice(&self.bits().to_ne_bytes())
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Nla80211ScanFreqNla {
    index: u16,
    freq: u32,
}

impl Nla for Nla80211ScanFreqNla {
    fn value_len(&self) -> usize {
        4
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        write_u32(buffer, self.freq)
    }

    fn kind(&self) -> u16 {
        self.index
    }
}

pub(crate) struct Nla80211ScanFreqNlas(Vec<Nla80211ScanFreqNla>);

impl std::ops::Deref for Nla80211ScanFreqNlas {
    type Target = Vec<Nla80211ScanFreqNla>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<&Vec<u32>> for Nla80211ScanFreqNlas {
    fn from(freqs: &Vec<u32>) -> Self {
        let mut nlas = Vec::new();
        for (i, freq) in freqs.iter().enumerate() {
            let nla = Nla80211ScanFreqNla {
                index: i as u16,
                freq: *freq,
            };
            nlas.push(nla);
        }
        Nla80211ScanFreqNlas(nlas)
    }
}

impl From<Nla80211ScanFreqNlas> for Vec<u32> {
    fn from(freqs: Nla80211ScanFreqNlas) -> Self {
        let mut freqs = freqs;
        freqs.0.drain(..).map(|c| c.freq).collect()
    }
}

impl Nla80211ScanFreqNlas {
    pub(crate) fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let mut freqs: Vec<Nla80211ScanFreqNla> = Vec::new();
        for (index, nla) in NlasIterator::new(payload).enumerate() {
            let error_msg =
                format!("Invalid NL80211_ATTR_SCAN_FREQUENCIES: {nla:?}");
            let nla = &nla.context(error_msg.clone())?;
            let freq = parse_u32(nla.value()).context(format!(
                "Invalid NL80211_ATTR_SCAN_FREQUENCIES: {nla:?}"
            ))?;
            freqs.push(Nla80211ScanFreqNla {
                index: index as u16,
                freq,
            });
        }
        Ok(Self(freqs))
    }
}
