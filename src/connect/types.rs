// SPDX-License-Identifier: MIT

/// Authentication type, used by `NL80211_CMD_CONNECT` and
/// `NL80211_CMD_AUTHENTICATE`.
///
/// Mirrors the stable values of the kernel `enum nl80211_auth_type`. Values
/// that are not (yet) modelled here -- including the version-dependent
/// `NL80211_AUTHTYPE_AUTOMATIC` -- are represented by
/// [`Nl80211AuthType::Other`].
#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
#[non_exhaustive]
pub enum Nl80211AuthType {
    /// Open System authentication.
    #[default]
    OpenSystem,
    /// Shared Key authentication (WEP only).
    SharedKey,
    /// Fast BSS Transition (802.11r).
    Ft,
    /// Network EAP (Cisco proprietary).
    NetworkEap,
    /// Simultaneous Authentication of Equals (WPA3-Personal).
    Sae,
    /// Fast Initial Link Setup shared key, without PFS.
    FilsSk,
    /// Fast Initial Link Setup shared key, with PFS.
    FilsSkPfs,
    /// Fast Initial Link Setup public key.
    FilsPk,
    /// Any other / kernel-version-specific value.
    Other(u32),
}

const NL80211_AUTHTYPE_OPEN_SYSTEM: u32 = 0;
const NL80211_AUTHTYPE_SHARED_KEY: u32 = 1;
const NL80211_AUTHTYPE_FT: u32 = 2;
const NL80211_AUTHTYPE_NETWORK_EAP: u32 = 3;
const NL80211_AUTHTYPE_SAE: u32 = 4;
const NL80211_AUTHTYPE_FILS_SK: u32 = 5;
const NL80211_AUTHTYPE_FILS_SK_PFS: u32 = 6;
const NL80211_AUTHTYPE_FILS_PK: u32 = 7;

impl From<u32> for Nl80211AuthType {
    fn from(d: u32) -> Self {
        match d {
            NL80211_AUTHTYPE_OPEN_SYSTEM => Self::OpenSystem,
            NL80211_AUTHTYPE_SHARED_KEY => Self::SharedKey,
            NL80211_AUTHTYPE_FT => Self::Ft,
            NL80211_AUTHTYPE_NETWORK_EAP => Self::NetworkEap,
            NL80211_AUTHTYPE_SAE => Self::Sae,
            NL80211_AUTHTYPE_FILS_SK => Self::FilsSk,
            NL80211_AUTHTYPE_FILS_SK_PFS => Self::FilsSkPfs,
            NL80211_AUTHTYPE_FILS_PK => Self::FilsPk,
            _ => Self::Other(d),
        }
    }
}

impl From<Nl80211AuthType> for u32 {
    fn from(v: Nl80211AuthType) -> u32 {
        match v {
            Nl80211AuthType::OpenSystem => NL80211_AUTHTYPE_OPEN_SYSTEM,
            Nl80211AuthType::SharedKey => NL80211_AUTHTYPE_SHARED_KEY,
            Nl80211AuthType::Ft => NL80211_AUTHTYPE_FT,
            Nl80211AuthType::NetworkEap => NL80211_AUTHTYPE_NETWORK_EAP,
            Nl80211AuthType::Sae => NL80211_AUTHTYPE_SAE,
            Nl80211AuthType::FilsSk => NL80211_AUTHTYPE_FILS_SK,
            Nl80211AuthType::FilsSkPfs => NL80211_AUTHTYPE_FILS_SK_PFS,
            Nl80211AuthType::FilsPk => NL80211_AUTHTYPE_FILS_PK,
            Nl80211AuthType::Other(d) => d,
        }
    }
}

/// Whether management frame protection (IEEE 802.11w, PMF) is used for a
/// connection. Mirrors the kernel `enum nl80211_mfp`.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
#[non_exhaustive]
pub enum Nl80211UseMfp {
    /// Management frame protection not used.
    #[default]
    No,
    /// Management frame protection required (mandatory for WPA3).
    Required,
    /// Management frame protection used if the AP supports it.
    Optional,
    /// Any other / kernel-version-specific value.
    Other(u32),
}

const NL80211_MFP_NO: u32 = 0;
const NL80211_MFP_REQUIRED: u32 = 1;
const NL80211_MFP_OPTIONAL: u32 = 2;

impl From<u32> for Nl80211UseMfp {
    fn from(d: u32) -> Self {
        match d {
            NL80211_MFP_NO => Self::No,
            NL80211_MFP_REQUIRED => Self::Required,
            NL80211_MFP_OPTIONAL => Self::Optional,
            _ => Self::Other(d),
        }
    }
}

impl From<Nl80211UseMfp> for u32 {
    fn from(v: Nl80211UseMfp) -> u32 {
        match v {
            Nl80211UseMfp::No => NL80211_MFP_NO,
            Nl80211UseMfp::Required => NL80211_MFP_REQUIRED,
            Nl80211UseMfp::Optional => NL80211_MFP_OPTIONAL,
            Nl80211UseMfp::Other(d) => d,
        }
    }
}

bitflags::bitflags! {
    /// Enabled WPA/RSN version(s), used with `NL80211_CMD_CONNECT`.
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    pub struct Nl80211WpaVersions: u32 {
        /// WPA version 1 (deprecated).
        const WPA1 = 1 << 0;
        /// WPA version 2 / RSN. WPA3-Personal (SAE) also uses RSN, so this
        /// bit is what most drivers expect for a WPA3 connection.
        const WPA2 = 1 << 1;
        /// WPA version 3.
        const WPA3 = 1 << 2;
    }
}

/// External authentication action, used with `NL80211_CMD_EXTERNAL_AUTH`.
///
/// Mirrors the kernel `enum nl80211_external_auth_action`. The kernel sends
/// [`Nl80211ExternalAuthAction::Start`] (or `Abort`) to userspace to drive an
/// external SAE authentication.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
#[non_exhaustive]
pub enum Nl80211ExternalAuthAction {
    /// Start external authentication.
    #[default]
    Start,
    /// Abort external authentication.
    Abort,
    /// Any other / kernel-version-specific value.
    Other(u32),
}

const NL80211_EXTERNAL_AUTH_START: u32 = 0;
const NL80211_EXTERNAL_AUTH_ABORT: u32 = 1;

impl From<u32> for Nl80211ExternalAuthAction {
    fn from(d: u32) -> Self {
        match d {
            NL80211_EXTERNAL_AUTH_START => Self::Start,
            NL80211_EXTERNAL_AUTH_ABORT => Self::Abort,
            _ => Self::Other(d),
        }
    }
}

impl From<Nl80211ExternalAuthAction> for u32 {
    fn from(v: Nl80211ExternalAuthAction) -> u32 {
        match v {
            Nl80211ExternalAuthAction::Start => NL80211_EXTERNAL_AUTH_START,
            Nl80211ExternalAuthAction::Abort => NL80211_EXTERNAL_AUTH_ABORT,
            Nl80211ExternalAuthAction::Other(d) => d,
        }
    }
}
