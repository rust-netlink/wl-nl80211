// SPDX-License-Identifier: MIT

// Most documentation comments are copied and modified from linux kernel
// include/uapi/linux/nl80211.h which is holding these license disclaimer:
/*
 * 802.11 netlink interface public header
 *
 * Copyright 2006-2010 Johannes Berg <johannes@sipsolutions.net>
 * Copyright 2008 Michael Wu <flamingice@sourmilk.net>
 * Copyright 2008 Luis Carlos Cobo <luisca@cozybit.com>
 * Copyright 2008 Michael Buesch <m@bues.ch>
 * Copyright 2008, 2009 Luis R. Rodriguez <lrodriguez@atheros.com>
 * Copyright 2008 Jouni Malinen <jouni.malinen@atheros.com>
 * Copyright 2008 Colin McCabe <colin@cozybit.com>
 * Copyright 2015-2017	Intel Deutschland GmbH
 * Copyright (C) 2018-2024 Intel Corporation
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 */

use anyhow::Context;
use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer, NlasIterator},
    parsers::{parse_string, parse_u16, parse_u32, parse_u64, parse_u8},
    DecodeError, Emitable, Parseable, ParseableParametrized,
};

use crate::{
    bytes::{write_u16, write_u32, write_u64},
    scan::{Nla80211ScanFreqNlas, Nla80211ScanSsidNlas},
    wiphy::Nl80211Commands,
    Nl80211Band, Nl80211BandTypes, Nl80211BssInfo, Nl80211ChannelWidth,
    Nl80211CipherSuit, Nl80211Command, Nl80211ExtFeature, Nl80211ExtFeatures,
    Nl80211ExtendedCapability, Nl80211Features, Nl80211HtCapabilityMask,
    Nl80211HtWiphyChannelType, Nl80211IfMode, Nl80211IfTypeExtCapa,
    Nl80211IfTypeExtCapas, Nl80211IfaceComb, Nl80211IfaceFrameType,
    Nl80211InterfaceType, Nl80211InterfaceTypes, Nl80211MloLink,
    Nl80211ScanFlags, Nl80211SchedScanMatch, Nl80211SchedScanPlan,
    Nl80211StationInfo, Nl80211SurveyInfo, Nl80211TransmitQueueStat,
    Nl80211VhtCapability, Nl80211WowlanTrigersSupport,
};

const ETH_ALEN: usize = 6;

struct MacAddressNlas(Vec<MacAddressNla>);

impl std::ops::Deref for MacAddressNlas {
    type Target = Vec<MacAddressNla>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<&Vec<[u8; ETH_ALEN]>> for MacAddressNlas {
    fn from(macs: &Vec<[u8; ETH_ALEN]>) -> Self {
        let mut nlas = Vec::new();
        for (i, mac) in macs.iter().enumerate() {
            let nla = MacAddressNla {
                index: i as u16,
                mac: *mac,
            };
            nlas.push(nla);
        }
        MacAddressNlas(nlas)
    }
}

impl From<MacAddressNlas> for Vec<[u8; ETH_ALEN]> {
    fn from(macs: MacAddressNlas) -> Self {
        let mut macs = macs;
        macs.0.drain(..).map(|c| c.mac).collect()
    }
}

impl MacAddressNlas {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let mut macs: Vec<MacAddressNla> = Vec::new();
        for (index, nla) in NlasIterator::new(payload).enumerate() {
            let error_msg = format!("Invalid NL80211_ATTR_MAC_ADDRS: {nla:?}");
            let nla = &nla.context(error_msg.clone())?;
            let mut mac = [0u8; ETH_ALEN];
            mac.copy_from_slice(&nla.value()[..ETH_ALEN]);
            macs.push(MacAddressNla {
                index: index as u16,
                mac,
            });
        }
        Ok(Self(macs))
    }
}

struct MacAddressNla {
    index: u16,
    mac: [u8; ETH_ALEN],
}

impl Nla for MacAddressNla {
    fn value_len(&self) -> usize {
        ETH_ALEN
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        buffer[..ETH_ALEN].copy_from_slice(&self.mac)
    }

    fn kind(&self) -> u16 {
        self.index
    }
}

// const NL80211_ATTR_UNSPEC:u16 = 0;
const NL80211_ATTR_WIPHY: u16 = 1;
const NL80211_ATTR_WIPHY_NAME: u16 = 2;
const NL80211_ATTR_IFINDEX: u16 = 3;
const NL80211_ATTR_IFNAME: u16 = 4;
const NL80211_ATTR_IFTYPE: u16 = 5;
const NL80211_ATTR_MAC: u16 = 6;
// const NL80211_ATTR_KEY_DATA:u16 = 7;
// const NL80211_ATTR_KEY_IDX:u16 = 8;
// const NL80211_ATTR_KEY_CIPHER:u16 = 9;
// const NL80211_ATTR_KEY_SEQ:u16 = 10;
// const NL80211_ATTR_KEY_DEFAULT:u16 = 11;
// const NL80211_ATTR_BEACON_INTERVAL:u16 = 12;
// const NL80211_ATTR_DTIM_PERIOD:u16 = 13;
// const NL80211_ATTR_BEACON_HEAD:u16 = 14;
// const NL80211_ATTR_BEACON_TAIL:u16 = 15;
// const NL80211_ATTR_STA_AID:u16 = 16;
// const NL80211_ATTR_STA_FLAGS:u16 = 17;
// const NL80211_ATTR_STA_LISTEN_INTERVAL:u16 = 18;
// const NL80211_ATTR_STA_SUPPORTED_RATES:u16 = 19;
// const NL80211_ATTR_STA_VLAN:u16 = 20;
const NL80211_ATTR_STA_INFO: u16 = 21;
const NL80211_ATTR_WIPHY_BANDS: u16 = 22;
// const NL80211_ATTR_MNTR_FLAGS:u16 = 23;
// const NL80211_ATTR_MESH_ID:u16 = 24;
// const NL80211_ATTR_STA_PLINK_ACTION:u16 = 25;
// const NL80211_ATTR_MPATH_NEXT_HOP:u16 = 26;
// const NL80211_ATTR_MPATH_INFO:u16 = 27;
// const NL80211_ATTR_BSS_CTS_PROT:u16 = 28;
// const NL80211_ATTR_BSS_SHORT_PREAMBLE:u16 = 29;
// const NL80211_ATTR_BSS_SHORT_SLOT_TIME:u16 = 30;
// const NL80211_ATTR_HT_CAPABILITY:u16 = 31;
const NL80211_ATTR_SUPPORTED_IFTYPES: u16 = 32;
// const NL80211_ATTR_REG_ALPHA2:u16 = 33;
// const NL80211_ATTR_REG_RULES:u16 = 34;
// const NL80211_ATTR_MESH_CONFIG:u16 = 35;
// const NL80211_ATTR_BSS_BASIC_RATES:u16 = 36;
// const NL80211_ATTR_WIPHY_TXQ_PARAMS:u16 = 37;
const NL80211_ATTR_WIPHY_FREQ: u16 = 38;
const NL80211_ATTR_WIPHY_CHANNEL_TYPE: u16 = 39;
// const NL80211_ATTR_KEY_DEFAULT_MGMT:u16 = 40;
// const NL80211_ATTR_MGMT_SUBTYPE:u16 = 41;
// const NL80211_ATTR_IE:u16 = 42;
const NL80211_ATTR_MAX_NUM_SCAN_SSIDS: u16 = 43;
const NL80211_ATTR_SCAN_FREQUENCIES: u16 = 44;
const NL80211_ATTR_SCAN_SSIDS: u16 = 45;
const NL80211_ATTR_GENERATION: u16 = 46;
const NL80211_ATTR_BSS: u16 = 47;
// const NL80211_ATTR_REG_INITIATOR:u16 = 48;
// const NL80211_ATTR_REG_TYPE:u16 = 49;
const NL80211_ATTR_SUPPORTED_COMMANDS: u16 = 50;
// const NL80211_ATTR_FRAME:u16 = 51;
const NL80211_ATTR_SSID: u16 = 52;
// const NL80211_ATTR_AUTH_TYPE:u16 = 53;
// const NL80211_ATTR_REASON_CODE:u16 = 54;
// const NL80211_ATTR_KEY_TYPE:u16 = 55;
const NL80211_ATTR_MAX_SCAN_IE_LEN: u16 = 56;
const NL80211_ATTR_CIPHER_SUITES: u16 = 57;
// const NL80211_ATTR_FREQ_BEFORE:u16 = 58;
// const NL80211_ATTR_FREQ_AFTER:u16 = 59;
// const NL80211_ATTR_FREQ_FIXED:u16 = 60;
const NL80211_ATTR_WIPHY_RETRY_SHORT: u16 = 61;
const NL80211_ATTR_WIPHY_RETRY_LONG: u16 = 62;
const NL80211_ATTR_WIPHY_FRAG_THRESHOLD: u16 = 63;
const NL80211_ATTR_WIPHY_RTS_THRESHOLD: u16 = 64;
// const NL80211_ATTR_TIMED_OUT:u16 = 65;
// const NL80211_ATTR_USE_MFP:u16 = 66;
// const NL80211_ATTR_STA_FLAGS2:u16 = 67;
// const NL80211_ATTR_CONTROL_PORT:u16 = 68;
// const NL80211_ATTR_TESTDATA:u16 = 69;
// const NL80211_ATTR_PRIVACY:u16 = 70;
// const NL80211_ATTR_DISCONNECTED_BY_AP:u16 = 71;
// const NL80211_ATTR_STATUS_CODE:u16 = 72;
// const NL80211_ATTR_CIPHER_SUITES_PAIRWISE:u16 = 73;
// const NL80211_ATTR_CIPHER_SUITE_GROUP:u16 = 74;
// const NL80211_ATTR_WPA_VERSIONS:u16 = 75;
// const NL80211_ATTR_AKM_SUITES:u16 = 76;
// const NL80211_ATTR_REQ_IE:u16 = 77;
// const NL80211_ATTR_RESP_IE:u16 = 78;
// const NL80211_ATTR_PREV_BSSID:u16 = 79;
// const NL80211_ATTR_KEY:u16 = 80;
// const NL80211_ATTR_KEYS:u16 = 81;
// const NL80211_ATTR_PID:u16 = 82;
const NL80211_ATTR_4ADDR: u16 = 83;
const NL80211_ATTR_SURVEY_INFO: u16 = 84;
// const NL80211_ATTR_PMKID:u16 = 85;
const NL80211_ATTR_MAX_NUM_PMKIDS: u16 = 86;
// const NL80211_ATTR_DURATION:u16 = 87;
// const NL80211_ATTR_COOKIE:u16 = 88;
const NL80211_ATTR_WIPHY_COVERAGE_CLASS: u16 = 89;
// const NL80211_ATTR_TX_RATES:u16 = 90;
// const NL80211_ATTR_FRAME_MATCH:u16 = 91;
// const NL80211_ATTR_ACK:u16 = 92;
// const NL80211_ATTR_PS_STATE:u16 = 93;
// const NL80211_ATTR_CQM:u16 = 94;
// const NL80211_ATTR_LOCAL_STATE_CHANGE:u16 = 95;
// const NL80211_ATTR_AP_ISOLATE:u16 = 96;
// const NL80211_ATTR_WIPHY_TX_POWER_SETTING:u16 = 97;
const NL80211_ATTR_WIPHY_TX_POWER_LEVEL: u16 = 98;
const NL80211_ATTR_TX_FRAME_TYPES: u16 = 99;
const NL80211_ATTR_RX_FRAME_TYPES: u16 = 100;
// Covered by frame_type.rs
// const NL80211_ATTR_FRAME_TYPE:u16 = 101;
const NL80211_ATTR_CONTROL_PORT_ETHERTYPE: u16 = 102;
// const NL80211_ATTR_CONTROL_PORT_NO_ENCRYPT:u16 = 103;
const NL80211_ATTR_SUPPORT_IBSS_RSN: u16 = 104;
const NL80211_ATTR_WIPHY_ANTENNA_TX: u16 = 105;
const NL80211_ATTR_WIPHY_ANTENNA_RX: u16 = 106;
// const NL80211_ATTR_MCAST_RATE:u16 = 107;
const NL80211_ATTR_OFFCHANNEL_TX_OK: u16 = 108;
// const NL80211_ATTR_BSS_HT_OPMODE:u16 = 109;
// const NL80211_ATTR_KEY_DEFAULT_TYPES:u16 = 110;
const NL80211_ATTR_MAX_REMAIN_ON_CHANNEL_DURATION: u16 = 111;
// const NL80211_ATTR_MESH_SETUP:u16 = 112;
const NL80211_ATTR_WIPHY_ANTENNA_AVAIL_TX: u16 = 113;
const NL80211_ATTR_WIPHY_ANTENNA_AVAIL_RX: u16 = 114;
const NL80211_ATTR_SUPPORT_MESH_AUTH: u16 = 115;
// const NL80211_ATTR_STA_PLINK_STATE:u16 = 116;
// const NL80211_ATTR_WOWLAN_TRIGGERS:u16 = 117;
const NL80211_ATTR_WOWLAN_TRIGGERS_SUPPORTED: u16 = 118;
const NL80211_ATTR_SCHED_SCAN_INTERVAL: u16 = 119;
const NL80211_ATTR_INTERFACE_COMBINATIONS: u16 = 120;
const NL80211_ATTR_SOFTWARE_IFTYPES: u16 = 121;
// const NL80211_ATTR_REKEY_DATA:u16 = 122;
const NL80211_ATTR_MAX_NUM_SCHED_SCAN_SSIDS: u16 = 123;
const NL80211_ATTR_MAX_SCHED_SCAN_IE_LEN: u16 = 124;
// const NL80211_ATTR_SCAN_SUPP_RATES:u16 = 125;
// const NL80211_ATTR_HIDDEN_SSID:u16 = 126;
// const NL80211_ATTR_IE_PROBE_RESP:u16 = 127;
// const NL80211_ATTR_IE_ASSOC_RESP:u16 = 128;
// const NL80211_ATTR_STA_WME:u16 = 129;
const NL80211_ATTR_SUPPORT_AP_UAPSD: u16 = 130;
const NL80211_ATTR_ROAM_SUPPORT: u16 = 131;
const NL80211_ATTR_SCHED_SCAN_MATCH: u16 = 132;
const NL80211_ATTR_MAX_MATCH_SETS: u16 = 133;
// const NL80211_ATTR_PMKSA_CANDIDATE:u16 = 134;
// const NL80211_ATTR_TX_NO_CCK_RATE:u16 = 135;
// const NL80211_ATTR_TDLS_ACTION:u16 = 136;
// const NL80211_ATTR_TDLS_DIALOG_TOKEN:u16 = 137;
// const NL80211_ATTR_TDLS_OPERATION:u16 = 138;
const NL80211_ATTR_TDLS_SUPPORT: u16 = 139;
const NL80211_ATTR_TDLS_EXTERNAL_SETUP: u16 = 140;
// const NL80211_ATTR_DEVICE_AP_SME:u16 = 141;
// const NL80211_ATTR_DONT_WAIT_FOR_ACK:u16 = 142;
const NL80211_ATTR_FEATURE_FLAGS: u16 = 143;
const NL80211_ATTR_PROBE_RESP_OFFLOAD: u16 = 144;
// const NL80211_ATTR_PROBE_RESP:u16 = 145;
// const NL80211_ATTR_DFS_REGION:u16 = 146;
// const NL80211_ATTR_DISABLE_HT:u16 = 147;
const NL80211_ATTR_HT_CAPABILITY_MASK: u16 = 148;
// const NL80211_ATTR_NOACK_MAP:u16 = 149;
// const NL80211_ATTR_INACTIVITY_TIMEOUT:u16 = 150;
// const NL80211_ATTR_RX_SIGNAL_DBM:u16 = 151;
// const NL80211_ATTR_BG_SCAN_PERIOD:u16 = 152;
const NL80211_ATTR_WDEV: u16 = 153;
// const NL80211_ATTR_USER_REG_HINT_TYPE:u16 = 154;
// const NL80211_ATTR_CONN_FAILED_REASON:u16 = 155;
// const NL80211_ATTR_AUTH_DATA:u16 = 156;
const NL80211_ATTR_VHT_CAPABILITY: u16 = 157;
const NL80211_ATTR_SCAN_FLAGS: u16 = 158;
const NL80211_ATTR_CHANNEL_WIDTH: u16 = 159;
const NL80211_ATTR_CENTER_FREQ1: u16 = 160;
const NL80211_ATTR_CENTER_FREQ2: u16 = 161;
// const NL80211_ATTR_P2P_CTWINDOW:u16 = 162;
// const NL80211_ATTR_P2P_OPPPS:u16 = 163;
// const NL80211_ATTR_LOCAL_MESH_POWER_MODE:u16 = 164;
// const NL80211_ATTR_ACL_POLICY:u16 = 165;
const NL80211_ATTR_MAC_ADDRS: u16 = 166;
// const NL80211_ATTR_MAC_ACL_MAX:u16 = 167;
// const NL80211_ATTR_RADAR_EVENT:u16 = 168;
const NL80211_ATTR_EXT_CAPA: u16 = 169;
const NL80211_ATTR_EXT_CAPA_MASK: u16 = 170;
// const NL80211_ATTR_STA_CAPABILITY:u16 = 171;
// const NL80211_ATTR_STA_EXT_CAPABILITY:u16 = 172;
// const NL80211_ATTR_PROTOCOL_FEATURES:u16 = 173;
const NL80211_ATTR_SPLIT_WIPHY_DUMP: u16 = 174;
// const NL80211_ATTR_DISABLE_VHT:u16 = 175;
const NL80211_ATTR_VHT_CAPABILITY_MASK: u16 = 176;
// const NL80211_ATTR_MDID:u16 = 177;
// const NL80211_ATTR_IE_RIC:u16 = 178;
// const NL80211_ATTR_CRIT_PROT_ID:u16 = 179;
// const NL80211_ATTR_MAX_CRIT_PROT_DURATION:u16 = 180;
// const NL80211_ATTR_PEER_AID:u16 = 181;
// const NL80211_ATTR_COALESCE_RULE:u16 = 182;
// const NL80211_ATTR_CH_SWITCH_COUNT:u16 = 183;
// const NL80211_ATTR_CH_SWITCH_BLOCK_TX:u16 = 184;
// const NL80211_ATTR_CSA_IES:u16 = 185;
// const NL80211_ATTR_CNTDWN_OFFS_BEACON:u16 = 186;
// const NL80211_ATTR_CNTDWN_OFFS_PRESP:u16 = 187;
// const NL80211_ATTR_RXMGMT_FLAGS:u16 = 188;
// const NL80211_ATTR_STA_SUPPORTED_CHANNELS:u16 = 189;
// const NL80211_ATTR_STA_SUPPORTED_OPER_CLASSES:u16 = 190;
// const NL80211_ATTR_HANDLE_DFS:u16 = 191;
// const NL80211_ATTR_SUPPORT_5_MHZ:u16 = 192;
// const NL80211_ATTR_SUPPORT_10_MHZ:u16 = 193;
// const NL80211_ATTR_OPMODE_NOTIF:u16 = 194;
// const NL80211_ATTR_VENDOR_ID:u16 = 195;
// const NL80211_ATTR_VENDOR_SUBCMD:u16 = 196;
// const NL80211_ATTR_VENDOR_DATA:u16 = 197;
// const NL80211_ATTR_VENDOR_EVENTS:u16 = 198;
// const NL80211_ATTR_QOS_MAP:u16 = 199;
// const NL80211_ATTR_MAC_HINT:u16 = 200;
// const NL80211_ATTR_WIPHY_FREQ_HINT:u16 = 201;
// const NL80211_ATTR_MAX_AP_ASSOC_STA:u16 = 202;
// const NL80211_ATTR_TDLS_PEER_CAPABILITY:u16 = 203;
// const NL80211_ATTR_SOCKET_OWNER:u16 = 204;
// const NL80211_ATTR_CSA_C_OFFSETS_TX:u16 = 205;
const NL80211_ATTR_MAX_CSA_COUNTERS: u16 = 206;
// const NL80211_ATTR_TDLS_INITIATOR:u16 = 207;
// const NL80211_ATTR_USE_RRM:u16 = 208;
// const NL80211_ATTR_WIPHY_DYN_ACK:u16 = 209;
// const NL80211_ATTR_TSID:u16 = 210;
// const NL80211_ATTR_USER_PRIO:u16 = 211;
// const NL80211_ATTR_ADMITTED_TIME:u16 = 212;
// const NL80211_ATTR_SMPS_MODE:u16 = 213;
// const NL80211_ATTR_OPER_CLASS:u16 = 214;
const NL80211_ATTR_MAC_MASK: u16 = 215;
const NL80211_ATTR_WIPHY_SELF_MANAGED_REG: u16 = 216;
const NL80211_ATTR_EXT_FEATURES: u16 = 217;
const NL80211_ATTR_SURVEY_RADIO_STATS: u16 = 218;
// const NL80211_ATTR_NETNS_FD:u16 = 219;
const NL80211_ATTR_SCHED_SCAN_DELAY: u16 = 220;
// const NL80211_ATTR_REG_INDOOR:u16 = 221;
const NL80211_ATTR_MAX_NUM_SCHED_SCAN_PLANS: u16 = 222;
const NL80211_ATTR_MAX_SCAN_PLAN_INTERVAL: u16 = 223;
const NL80211_ATTR_MAX_SCAN_PLAN_ITERATIONS: u16 = 224;
const NL80211_ATTR_SCHED_SCAN_PLANS: u16 = 225;
// const NL80211_ATTR_PBSS:u16 = 226;
// const NL80211_ATTR_BSS_SELECT:u16 = 227;
// const NL80211_ATTR_STA_SUPPORT_P2P_PS:u16 = 228;
// const NL80211_ATTR_PAD:u16 = 229;
const NL80211_ATTR_IFTYPE_EXT_CAPA: u16 = 230;
// const NL80211_ATTR_MU_MIMO_GROUP_DATA:u16 = 231;
// const NL80211_ATTR_MU_MIMO_FOLLOW_MAC_ADDR:u16 = 232;
// const NL80211_ATTR_SCAN_START_TIME_TSF:u16 = 233;
// const NL80211_ATTR_SCAN_START_TIME_TSF_BSSID:u16 = 234;
const NL80211_ATTR_MEASUREMENT_DURATION: u16 = 235;
// const NL80211_ATTR_MEASUREMENT_DURATION_MANDATORY:u16 = 236;
// const NL80211_ATTR_MESH_PEER_AID:u16 = 237;
// const NL80211_ATTR_NAN_MASTER_PREF:u16 = 238;
const NL80211_ATTR_BANDS: u16 = 239;
// const NL80211_ATTR_NAN_FUNC:u16 = 240;
// const NL80211_ATTR_NAN_MATCH:u16 = 241;
// const NL80211_ATTR_FILS_KEK:u16 = 242;
// const NL80211_ATTR_FILS_NONCES:u16 = 243;
// const NL80211_ATTR_MULTICAST_TO_UNICAST_ENABLED:u16 = 244;
// const NL80211_ATTR_BSSID:u16 = 245;
// const NL80211_ATTR_SCHED_SCAN_RELATIVE_RSSI:u16 = 246;
// const NL80211_ATTR_SCHED_SCAN_RSSI_ADJUST:u16 = 247;
// const NL80211_ATTR_TIMEOUT_REASON:u16 = 248;
// const NL80211_ATTR_FILS_ERP_USERNAME:u16 = 249;
// const NL80211_ATTR_FILS_ERP_REALM:u16 = 250;
// const NL80211_ATTR_FILS_ERP_NEXT_SEQ_NUM:u16 = 251;
// const NL80211_ATTR_FILS_ERP_RRK:u16 = 252;
// const NL80211_ATTR_FILS_CACHE_ID:u16 = 253;
// const NL80211_ATTR_PMK:u16 = 254;
// const NL80211_ATTR_SCHED_SCAN_MULTI:u16 = 255;
const NL80211_ATTR_SCHED_SCAN_MAX_REQS: u16 = 256;
// const NL80211_ATTR_WANT_1X_4WAY_HS:u16 = 257;
// const NL80211_ATTR_PMKR0_NAME:u16 = 258;
// const NL80211_ATTR_PORT_AUTHORIZED:u16 = 259;
// const NL80211_ATTR_EXTERNAL_AUTH_ACTION:u16 = 260;
// const NL80211_ATTR_EXTERNAL_AUTH_SUPPORT:u16 = 261;
// const NL80211_ATTR_NSS:u16 = 262;
// const NL80211_ATTR_ACK_SIGNAL:u16 = 263;
// const NL80211_ATTR_CONTROL_PORT_OVER_NL80211:u16 = 264;
const NL80211_ATTR_TXQ_STATS: u16 = 265;
const NL80211_ATTR_TXQ_LIMIT: u16 = 266;
const NL80211_ATTR_TXQ_MEMORY_LIMIT: u16 = 267;
const NL80211_ATTR_TXQ_QUANTUM: u16 = 268;
// const NL80211_ATTR_HE_CAPABILITY:u16 = 269;
// const NL80211_ATTR_FTM_RESPONDER:u16 = 270;
// const NL80211_ATTR_FTM_RESPONDER_STATS:u16 = 271;
// const NL80211_ATTR_TIMEOUT:u16 = 272;
// const NL80211_ATTR_PEER_MEASUREMENTS:u16 = 273;
// const NL80211_ATTR_AIRTIME_WEIGHT:u16 = 274;
// const NL80211_ATTR_STA_TX_POWER_SETTING:u16 = 275;
// const NL80211_ATTR_STA_TX_POWER:u16 = 276;
// const NL80211_ATTR_SAE_PASSWORD:u16 = 277;
// const NL80211_ATTR_TWT_RESPONDER:u16 = 278;
// const NL80211_ATTR_HE_OBSS_PD:u16 = 279;
// const NL80211_ATTR_WIPHY_EDMG_CHANNELS:u16 = 280;
// const NL80211_ATTR_WIPHY_EDMG_BW_CONFIG:u16 = 281;
// const NL80211_ATTR_VLAN_ID:u16 = 282;
// const NL80211_ATTR_HE_BSS_COLOR:u16 = 283;
// const NL80211_ATTR_IFTYPE_AKM_SUITES:u16 = 284;
// const NL80211_ATTR_TID_CONFIG:u16 = 285;
// const NL80211_ATTR_CONTROL_PORT_NO_PREAUTH:u16 = 286;
// const NL80211_ATTR_PMK_LIFETIME:u16 = 287;
// const NL80211_ATTR_PMK_REAUTH_THRESHOLD:u16 = 288;
// const NL80211_ATTR_RECEIVE_MULTICAST:u16 = 289;
const NL80211_ATTR_WIPHY_FREQ_OFFSET: u16 = 290;
// const NL80211_ATTR_CENTER_FREQ1_OFFSET:u16 = 291;
// const NL80211_ATTR_SCAN_FREQ_KHZ:u16 = 292;
// const NL80211_ATTR_HE_6GHZ_CAPABILITY:u16 = 293;
// const NL80211_ATTR_FILS_DISCOVERY:u16 = 294;
// const NL80211_ATTR_UNSOL_BCAST_PROBE_RESP:u16 = 295;
// const NL80211_ATTR_S1G_CAPABILITY:u16 = 296;
// const NL80211_ATTR_S1G_CAPABILITY_MASK:u16 = 297;
// const NL80211_ATTR_SAE_PWE:u16 = 298;
// const NL80211_ATTR_RECONNECT_REQUESTED:u16 = 299;
// const NL80211_ATTR_SAR_SPEC:u16 = 300;
// const NL80211_ATTR_DISABLE_HE:u16 = 301;
// const NL80211_ATTR_OBSS_COLOR_BITMAP:u16 = 302;
// const NL80211_ATTR_COLOR_CHANGE_COUNT:u16 = 303;
// const NL80211_ATTR_COLOR_CHANGE_COLOR:u16 = 304;
// const NL80211_ATTR_COLOR_CHANGE_ELEMS:u16 = 305;
// const NL80211_ATTR_MBSSID_CONFIG:u16 = 306;
// const NL80211_ATTR_MBSSID_ELEMS:u16 = 307;
// const NL80211_ATTR_RADAR_BACKGROUND:u16 = 308;
// const NL80211_ATTR_AP_SETTINGS_FLAGS:u16 = 309;
// const NL80211_ATTR_EHT_CAPABILITY:u16 = 310;
// const NL80211_ATTR_DISABLE_EHT:u16 = 311;
const NL80211_ATTR_MLO_LINKS: u16 = 312;
// Covered in mlo.rs
// const NL80211_ATTR_MLO_LINK_ID: u16 = 313;
// const NL80211_ATTR_MLD_ADDR:u16 = 314;
// const NL80211_ATTR_MLO_SUPPORT:u16 = 315;
const NL80211_ATTR_MAX_NUM_AKM_SUITES: u16 = 316;
const NL80211_ATTR_EML_CAPABILITY: u16 = 317;
const NL80211_ATTR_MLD_CAPA_AND_OPS: u16 = 318;
// const NL80211_ATTR_TX_HW_TIMESTAMP:u16 = 319;
// const NL80211_ATTR_RX_HW_TIMESTAMP:u16 = 320;
// const NL80211_ATTR_TD_BITMAP:u16 = 321;
// const NL80211_ATTR_PUNCT_BITMAP:u16 = 322;
const NL80211_ATTR_MAX_HW_TIMESTAMP_PEERS: u16 = 323;
// const NL80211_ATTR_HW_TIMESTAMP_ENABLED:u16 = 324;
// const NL80211_ATTR_EMA_RNR_ELEMS:u16 = 325;
// const NL80211_ATTR_MLO_LINK_DISABLED:u16 = 326;
// const NL80211_ATTR_BSS_DUMP_INCLUDE_USE_DATA:u16 = 327;
// const NL80211_ATTR_MLO_TTLM_DLINK:u16 = 328;
// const NL80211_ATTR_MLO_TTLM_ULINK:u16 = 329;
// const NL80211_ATTR_ASSOC_SPP_AMSDU:u16 = 330;
// const NL80211_ATTR_WIPHY_RADIOS:u16 = 331;
// const NL80211_ATTR_WIPHY_INTERFACE_COMBINATIONS:u16 = 332;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum Nl80211Attr {
    Wiphy(u32),
    WiphyName(String),
    IfIndex(u32),
    IfName(String),
    IfType(Nl80211InterfaceType),
    IfTypeExtCap(Vec<Nl80211IfTypeExtCapa>),
    Mac([u8; ETH_ALEN]),
    MacMask([u8; ETH_ALEN]),
    MacAddrs(Vec<[u8; ETH_ALEN]>),
    Wdev(u64),
    Generation(u32),
    Use4Addr(bool),
    WiphyFreq(u32),
    WiphyFreqOffset(u32),
    WiphyChannelType(Nl80211HtWiphyChannelType),
    ChannelWidth(Nl80211ChannelWidth),
    CenterFreq1(u32),
    CenterFreq2(u32),
    WiphyTxPowerLevel(u32),
    Ssid(String),
    StationInfo(Vec<Nl80211StationInfo>),
    SurveyInfo(Vec<Nl80211SurveyInfo>),
    TransmitQueueStats(Vec<Nl80211TransmitQueueStat>),
    TransmitQueueLimit(u32),
    TransmitQueueMemoryLimit(u32),
    TransmitQueueQuantum(u32),
    MloLinks(Vec<Nl80211MloLink>),
    WiphyRetryShort(u8),
    WiphyRetryLong(u8),
    WiphyFragThreshold(u32),
    WiphyRtsThreshold(u32),
    WiphyCoverageClass(u8),
    MaxNumScanSsids(u8),
    MaxNumSchedScanSsids(u8),
    MaxScanIeLen(u16),
    MaxSchedScanIeLen(u16),
    MaxMatchSets(u8),
    SupportIbssRsn,
    SupportMeshAuth,
    SupportApUapsd,
    RoamSupport,
    TdlsSupport,
    TdlsExternalSetup,
    CipherSuites(Vec<Nl80211CipherSuit>),
    MaxNumPmkids(u8),
    ControlPortEthertype,
    WiphyAntennaAvailTx(u32),
    WiphyAntennaAvailRx(u32),
    ApProbeRespOffload(u32),
    WiphyAntennaTx(u32),
    WiphyAntennaRx(u32),
    SupportedIftypes(Vec<Nl80211IfMode>),
    WiphyBands(Vec<Nl80211Band>),
    /// flag attribute, indicate userspace supports
    /// receiving the data for a single wiphy split across multiple
    /// messages, given with wiphy dump message
    SplitWiphyDump,
    SupportedCommand(Vec<Nl80211Command>),
    /// in milliseconds
    MaxRemainOnChannelDuration(u32),
    OffchannelTxOk,
    SurveyRadioStats,
    WowlanTrigersSupport(Vec<Nl80211WowlanTrigersSupport>),
    SoftwareIftypes(Vec<Nl80211InterfaceType>),
    Features(Nl80211Features),
    ExtFeatures(Vec<Nl80211ExtFeature>),
    InterfaceCombination(Vec<Nl80211IfaceComb>),
    HtCapabilityMask(Nl80211HtCapabilityMask),
    TxFrameTypes(Vec<Nl80211IfaceFrameType>),
    RxFrameTypes(Vec<Nl80211IfaceFrameType>),
    MaxNumSchedScanPlans(u32),
    MaxScanPlanInterval(u32),
    MaxScanPlanIterations(u32),
    ExtCap(Nl80211ExtendedCapability),
    ExtCapMask(Nl80211ExtendedCapability),
    VhtCap(Nl80211VhtCapability),
    VhtCapMask(Nl80211VhtCapability),
    MaxCsaCounters(u8),
    WiphySelfManagedReg,
    SchedScanMaxReqs(u32),
    EmlCapability(u16),
    MldCapaAndOps(u16),
    Bands(Nl80211BandTypes),
    /// Maximum number of AKM suites allowed for connect command.
    MaxNumAkmSuites(u16),
    /// Maximum number of peers that HW timestamping can be enabled for
    /// concurrently. A value of 0xffff indicates setting for all peers(i.e.
    /// not specifying an address with set hardware timestamp) is
    /// supported.
    MaxHwTimestampPeers(u16),
    /// Basic Service Set (BSS)
    Bss(Vec<Nl80211BssInfo>),
    ScanSsids(Vec<String>),
    ScanFlags(Nl80211ScanFlags),
    MeasurementDuration(u16),
    /// Scan interval in millisecond(ms)
    SchedScanInterval(u32),
    /// Delay before the first cycle of a scheduled scan is started.  Or the
    /// delay before a WoWLAN net-detect scan is started, counting from the
    /// moment the system is suspended. This value is in seconds.
    SchedScanDelay(u32),
    /// Scan frequencies in MHz.
    ScanFrequencies(Vec<u32>),
    /// Sets of attributes to match during scheduled scans. Only BSSs
    /// that match any of the sets will be reported. These are pass-thru
    /// filter rules. For a match to succeed, the BSS must match all
    /// attributes of a set. Since not every hardware supports matching all
    /// types of attributes, there is no guarantee that the reported BSSs are
    /// fully complying with the match sets and userspace needs to be able to
    /// ignore them by itself. Thus, the implementation is somewhat
    /// hardware-dependent, but this is only an optimization and the userspace
    /// application needs to handle all the non-filtered results anyway.
    SchedScanMatch(Vec<Nl80211SchedScanMatch>),
    /// A list of scan plans for scheduled scan. Each scan plan defines the
    /// number of scan iterations and the interval between scans. The last scan
    /// plan will always run infinitely, thus it must not specify the number of
    /// iterations, only the interval between scans. The scan plans are
    /// executed sequentially.
    SchedScanPlans(Vec<Nl80211SchedScanPlan>),
    Other(DefaultNla),
}

impl Nla for Nl80211Attr {
    fn value_len(&self) -> usize {
        match self {
            Self::IfIndex(_)
            | Self::Wiphy(_)
            | Self::IfType(_)
            | Self::Generation(_)
            | Self::WiphyFreq(_)
            | Self::WiphyFreqOffset(_)
            | Self::WiphyChannelType(_)
            | Self::CenterFreq1(_)
            | Self::CenterFreq2(_)
            | Self::WiphyTxPowerLevel(_)
            | Self::ChannelWidth(_)
            | Self::WiphyFragThreshold(_)
            | Self::WiphyRtsThreshold(_)
            | Self::WiphyAntennaAvailTx(_)
            | Self::WiphyAntennaAvailRx(_)
            | Self::ApProbeRespOffload(_)
            | Self::WiphyAntennaTx(_)
            | Self::WiphyAntennaRx(_)
            | Self::MaxNumSchedScanPlans(_)
            | Self::MaxScanPlanInterval(_)
            | Self::MaxScanPlanIterations(_)
            | Self::SchedScanMaxReqs(_)
            | Self::TransmitQueueLimit(_)
            | Self::TransmitQueueMemoryLimit(_)
            | Self::TransmitQueueQuantum(_)
            | Self::SchedScanInterval(_)
            | Self::SchedScanDelay(_) => 4,
            Self::Wdev(_) => 8,
            Self::IfName(s) | Self::Ssid(s) | Self::WiphyName(s) => s.len() + 1,
            Self::Mac(_) | Self::MacMask(_) => ETH_ALEN,
            Self::MacAddrs(s) => {
                MacAddressNlas::from(s).as_slice().buffer_len()
            }
            Self::Use4Addr(_) => 1,
            Self::WiphyRetryShort(_)
            | Self::WiphyRetryLong(_)
            | Self::WiphyCoverageClass(_)
            | Self::MaxNumScanSsids(_)
            | Self::MaxNumSchedScanSsids(_)
            | Self::MaxMatchSets(_)
            | Self::MaxNumPmkids(_) => 1,
            Self::TransmitQueueStats(nlas) => nlas.as_slice().buffer_len(),
            Self::StationInfo(nlas) => nlas.as_slice().buffer_len(),
            Self::SurveyInfo(nlas) => nlas.as_slice().buffer_len(),
            Self::MloLinks(links) => links.as_slice().buffer_len(),
            Self::MaxScanIeLen(_) | Self::MaxSchedScanIeLen(_) => 2,
            Self::SupportIbssRsn
            | Self::SupportMeshAuth
            | Self::SupportApUapsd
            | Self::RoamSupport
            | Self::TdlsSupport
            | Self::TdlsExternalSetup
            | Self::ControlPortEthertype
            | Self::OffchannelTxOk
            | Self::SurveyRadioStats
            | Self::WiphySelfManagedReg => 0,
            Self::CipherSuites(s) => 4 * s.len(),
            Self::SupportedIftypes(s) => s.as_slice().buffer_len(),
            Self::WiphyBands(s) => s.as_slice().buffer_len(),
            Self::SplitWiphyDump => 0,
            Self::SupportedCommand(s) => {
                Nl80211Commands::from(s).as_slice().buffer_len()
            }
            Self::MaxRemainOnChannelDuration(_) => 4,
            Self::WowlanTrigersSupport(s) => s.as_slice().buffer_len(),
            Self::SoftwareIftypes(s) => {
                Nl80211InterfaceTypes::from(s).as_slice().buffer_len()
            }
            Self::Features(_) => 4,
            Self::ExtFeatures(_) => Nl80211ExtFeatures::LENGTH,
            Self::InterfaceCombination(s) => s.as_slice().buffer_len(),
            Self::HtCapabilityMask(_) => Nl80211HtCapabilityMask::LENGTH,
            Self::TxFrameTypes(s) => s.as_slice().buffer_len(),
            Self::RxFrameTypes(s) => s.as_slice().buffer_len(),
            Self::ExtCap(v) => v.len(),
            Self::ExtCapMask(v) => v.len(),
            Self::VhtCap(v) => v.buffer_len(),
            Self::VhtCapMask(v) => v.buffer_len(),
            Self::MaxCsaCounters(_) => 1,
            Self::IfTypeExtCap(s) => {
                Nl80211IfTypeExtCapas::from(s).as_slice().buffer_len()
            }
            Self::EmlCapability(_)
            | Self::MldCapaAndOps(_)
            | Self::MaxNumAkmSuites(_)
            | Self::MaxHwTimestampPeers(_)
            | Self::MeasurementDuration(_) => 2,
            Self::Bands(_) => Nl80211BandTypes::LENGTH,
            Self::Bss(v) => v.as_slice().buffer_len(),
            Self::ScanSsids(v) => {
                Nla80211ScanSsidNlas::from(v).as_slice().buffer_len()
            }
            Self::ScanFlags(v) => v.buffer_len(),
            Self::ScanFrequencies(v) => {
                Nla80211ScanFreqNlas::from(v).as_slice().buffer_len()
            }
            Self::SchedScanMatch(v) => v.as_slice().buffer_len(),
            Self::SchedScanPlans(v) => v.as_slice().buffer_len(),
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Wiphy(_) => NL80211_ATTR_WIPHY,
            Self::WiphyName(_) => NL80211_ATTR_WIPHY_NAME,
            Self::IfIndex(_) => NL80211_ATTR_IFINDEX,
            Self::IfName(_) => NL80211_ATTR_IFNAME,
            Self::IfType(_) => NL80211_ATTR_IFTYPE,
            Self::Mac(_) => NL80211_ATTR_MAC,
            Self::MacMask(_) => NL80211_ATTR_MAC_MASK,
            Self::MacAddrs(_) => NL80211_ATTR_MAC_ADDRS,
            Self::Wdev(_) => NL80211_ATTR_WDEV,
            Self::Generation(_) => NL80211_ATTR_GENERATION,
            Self::Use4Addr(_) => NL80211_ATTR_4ADDR,
            Self::WiphyFreq(_) => NL80211_ATTR_WIPHY_FREQ,
            Self::WiphyFreqOffset(_) => NL80211_ATTR_WIPHY_FREQ_OFFSET,
            Self::WiphyChannelType(_) => NL80211_ATTR_WIPHY_CHANNEL_TYPE,
            Self::ChannelWidth(_) => NL80211_ATTR_CHANNEL_WIDTH,
            Self::CenterFreq1(_) => NL80211_ATTR_CENTER_FREQ1,
            Self::CenterFreq2(_) => NL80211_ATTR_CENTER_FREQ2,
            Self::WiphyTxPowerLevel(_) => NL80211_ATTR_WIPHY_TX_POWER_LEVEL,
            Self::Ssid(_) => NL80211_ATTR_SSID,
            Self::StationInfo(_) => NL80211_ATTR_STA_INFO,
            Self::SurveyInfo(_) => NL80211_ATTR_SURVEY_INFO,
            Self::SurveyRadioStats => NL80211_ATTR_SURVEY_RADIO_STATS,
            Self::TransmitQueueStats(_) => NL80211_ATTR_TXQ_STATS,
            Self::TransmitQueueLimit(_) => NL80211_ATTR_TXQ_LIMIT,
            Self::TransmitQueueMemoryLimit(_) => NL80211_ATTR_TXQ_MEMORY_LIMIT,
            Self::TransmitQueueQuantum(_) => NL80211_ATTR_TXQ_QUANTUM,
            Self::MloLinks(_) => NL80211_ATTR_MLO_LINKS,
            Self::WiphyRetryShort(_) => NL80211_ATTR_WIPHY_RETRY_SHORT,
            Self::WiphyRetryLong(_) => NL80211_ATTR_WIPHY_RETRY_LONG,
            Self::WiphyFragThreshold(_) => NL80211_ATTR_WIPHY_FRAG_THRESHOLD,
            Self::WiphyRtsThreshold(_) => NL80211_ATTR_WIPHY_RTS_THRESHOLD,
            Self::WiphyCoverageClass(_) => NL80211_ATTR_WIPHY_COVERAGE_CLASS,
            Self::MaxNumScanSsids(_) => NL80211_ATTR_MAX_NUM_SCAN_SSIDS,
            Self::MaxNumSchedScanSsids(_) => {
                NL80211_ATTR_MAX_NUM_SCHED_SCAN_SSIDS
            }
            Self::MaxScanIeLen(_) => NL80211_ATTR_MAX_SCAN_IE_LEN,
            Self::MaxSchedScanIeLen(_) => NL80211_ATTR_MAX_SCHED_SCAN_IE_LEN,
            Self::MaxMatchSets(_) => NL80211_ATTR_MAX_MATCH_SETS,
            Self::SupportIbssRsn => NL80211_ATTR_SUPPORT_IBSS_RSN,
            Self::SupportMeshAuth => NL80211_ATTR_SUPPORT_MESH_AUTH,
            Self::SupportApUapsd => NL80211_ATTR_SUPPORT_AP_UAPSD,
            Self::RoamSupport => NL80211_ATTR_ROAM_SUPPORT,
            Self::TdlsSupport => NL80211_ATTR_TDLS_SUPPORT,
            Self::TdlsExternalSetup => NL80211_ATTR_TDLS_EXTERNAL_SETUP,
            Self::CipherSuites(_) => NL80211_ATTR_CIPHER_SUITES,
            Self::MaxNumPmkids(_) => NL80211_ATTR_MAX_NUM_PMKIDS,
            Self::ControlPortEthertype => NL80211_ATTR_CONTROL_PORT_ETHERTYPE,
            Self::WiphyAntennaAvailTx(_) => NL80211_ATTR_WIPHY_ANTENNA_AVAIL_TX,
            Self::WiphyAntennaAvailRx(_) => NL80211_ATTR_WIPHY_ANTENNA_AVAIL_RX,
            Self::ApProbeRespOffload(_) => NL80211_ATTR_PROBE_RESP_OFFLOAD,
            Self::WiphyAntennaTx(_) => NL80211_ATTR_WIPHY_ANTENNA_TX,
            Self::WiphyAntennaRx(_) => NL80211_ATTR_WIPHY_ANTENNA_RX,
            Self::SupportedIftypes(_) => NL80211_ATTR_SUPPORTED_IFTYPES,
            Self::WiphyBands(_) => NL80211_ATTR_WIPHY_BANDS,
            Self::SplitWiphyDump => NL80211_ATTR_SPLIT_WIPHY_DUMP,
            Self::SupportedCommand(_) => NL80211_ATTR_SUPPORTED_COMMANDS,
            Self::MaxRemainOnChannelDuration(_) => {
                NL80211_ATTR_MAX_REMAIN_ON_CHANNEL_DURATION
            }
            Self::OffchannelTxOk => NL80211_ATTR_OFFCHANNEL_TX_OK,
            Self::WowlanTrigersSupport(_) => {
                NL80211_ATTR_WOWLAN_TRIGGERS_SUPPORTED
            }
            Self::SoftwareIftypes(_) => NL80211_ATTR_SOFTWARE_IFTYPES,
            Self::Features(_) => NL80211_ATTR_FEATURE_FLAGS,
            Self::ExtFeatures(_) => NL80211_ATTR_EXT_FEATURES,
            Self::InterfaceCombination(_) => {
                NL80211_ATTR_INTERFACE_COMBINATIONS
            }
            Self::HtCapabilityMask(_) => NL80211_ATTR_HT_CAPABILITY_MASK,
            Self::TxFrameTypes(_) => NL80211_ATTR_TX_FRAME_TYPES,
            Self::RxFrameTypes(_) => NL80211_ATTR_RX_FRAME_TYPES,
            Self::MaxNumSchedScanPlans(_) => {
                NL80211_ATTR_MAX_NUM_SCHED_SCAN_PLANS
            }
            Self::MaxScanPlanInterval(_) => NL80211_ATTR_MAX_SCAN_PLAN_INTERVAL,
            Self::MaxScanPlanIterations(_) => {
                NL80211_ATTR_MAX_SCAN_PLAN_ITERATIONS
            }
            Self::ExtCap(_) => NL80211_ATTR_EXT_CAPA,
            Self::ExtCapMask(_) => NL80211_ATTR_EXT_CAPA_MASK,
            Self::VhtCap(_) => NL80211_ATTR_VHT_CAPABILITY,
            Self::VhtCapMask(_) => NL80211_ATTR_VHT_CAPABILITY_MASK,
            Self::MaxCsaCounters(_) => NL80211_ATTR_MAX_CSA_COUNTERS,
            Self::WiphySelfManagedReg => NL80211_ATTR_WIPHY_SELF_MANAGED_REG,
            Self::SchedScanMaxReqs(_) => NL80211_ATTR_SCHED_SCAN_MAX_REQS,
            Self::IfTypeExtCap(_) => NL80211_ATTR_IFTYPE_EXT_CAPA,
            Self::EmlCapability(_) => NL80211_ATTR_EML_CAPABILITY,
            Self::MldCapaAndOps(_) => NL80211_ATTR_MLD_CAPA_AND_OPS,
            Self::Bands(_) => NL80211_ATTR_BANDS,
            Self::MaxNumAkmSuites(_) => NL80211_ATTR_MAX_NUM_AKM_SUITES,
            Self::MaxHwTimestampPeers(_) => NL80211_ATTR_MAX_HW_TIMESTAMP_PEERS,
            Self::Bss(_) => NL80211_ATTR_BSS,
            Self::ScanSsids(_) => NL80211_ATTR_SCAN_SSIDS,
            Self::ScanFlags(_) => NL80211_ATTR_SCAN_FLAGS,
            Self::MeasurementDuration(_) => NL80211_ATTR_MEASUREMENT_DURATION,
            Self::SchedScanInterval(_) => NL80211_ATTR_SCHED_SCAN_INTERVAL,
            Self::SchedScanDelay(_) => NL80211_ATTR_SCHED_SCAN_DELAY,
            Self::ScanFrequencies(_) => NL80211_ATTR_SCAN_FREQUENCIES,
            Self::SchedScanMatch(_) => NL80211_ATTR_SCHED_SCAN_MATCH,
            Self::SchedScanPlans(_) => NL80211_ATTR_SCHED_SCAN_PLANS,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::IfIndex(d)
            | Self::Wiphy(d)
            | Self::Generation(d)
            | Self::WiphyFreq(d)
            | Self::WiphyFreqOffset(d)
            | Self::CenterFreq1(d)
            | Self::CenterFreq2(d)
            | Self::WiphyTxPowerLevel(d)
            | Self::WiphyFragThreshold(d)
            | Self::WiphyRtsThreshold(d)
            | Self::WiphyAntennaAvailTx(d)
            | Self::WiphyAntennaAvailRx(d)
            | Self::ApProbeRespOffload(d)
            | Self::WiphyAntennaTx(d)
            | Self::WiphyAntennaRx(d)
            | Self::MaxNumSchedScanPlans(d)
            | Self::MaxScanPlanInterval(d)
            | Self::MaxScanPlanIterations(d)
            | Self::SchedScanMaxReqs(d)
            | Self::TransmitQueueLimit(d)
            | Self::TransmitQueueMemoryLimit(d)
            | Self::TransmitQueueQuantum(d)
            | Self::SchedScanInterval(d)
            | Self::SchedScanDelay(d) => write_u32(buffer, *d),
            Self::MaxScanIeLen(d) | Self::MaxSchedScanIeLen(d) => {
                write_u16(buffer, *d)
            }
            Self::Wdev(d) => write_u64(buffer, *d),
            Self::IfType(d) => write_u32(buffer, (*d).into()),
            Self::Mac(s) | Self::MacMask(s) => buffer.copy_from_slice(s),
            Self::MacAddrs(s) => {
                MacAddressNlas::from(s).as_slice().emit(buffer)
            }
            Self::IfName(s) | Self::Ssid(s) | Self::WiphyName(s) => {
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                buffer[s.len()] = 0;
            }
            Self::Use4Addr(d) => buffer[0] = *d as u8,
            Self::SupportIbssRsn
            | Self::SupportMeshAuth
            | Self::SupportApUapsd
            | Self::RoamSupport
            | Self::TdlsSupport
            | Self::TdlsExternalSetup
            | Self::ControlPortEthertype
            | Self::OffchannelTxOk
            | Self::SurveyRadioStats
            | Self::WiphySelfManagedReg => (),
            Self::WiphyChannelType(d) => write_u32(buffer, (*d).into()),
            Self::ChannelWidth(d) => write_u32(buffer, (*d).into()),
            Self::StationInfo(nlas) => nlas.as_slice().emit(buffer),
            Self::SurveyInfo(nlas) => nlas.as_slice().emit(buffer),
            Self::TransmitQueueStats(nlas) => nlas.as_slice().emit(buffer),
            Self::MloLinks(links) => links.as_slice().emit(buffer),
            Self::WiphyRetryShort(d)
            | Self::WiphyRetryLong(d)
            | Self::WiphyCoverageClass(d)
            | Self::MaxNumScanSsids(d)
            | Self::MaxNumSchedScanSsids(d)
            | Self::MaxMatchSets(d)
            | Self::MaxNumPmkids(d) => buffer[0] = *d,
            Self::CipherSuites(suits) => {
                let nums: Vec<u32> =
                    suits.as_slice().iter().map(|s| u32::from(*s)).collect();
                for (i, v) in nums.as_slice().iter().enumerate() {
                    buffer[i * 4..(i + 1) * 4]
                        .copy_from_slice(&v.to_ne_bytes());
                }
            }
            Self::SupportedIftypes(s) => s.as_slice().emit(buffer),
            Self::WiphyBands(s) => s.as_slice().emit(buffer),
            Self::SplitWiphyDump => (),
            Self::SupportedCommand(s) => {
                Nl80211Commands::from(s).as_slice().emit(buffer)
            }
            Self::MaxRemainOnChannelDuration(d) => write_u32(buffer, *d),
            Self::WowlanTrigersSupport(s) => s.as_slice().emit(buffer),
            Self::SoftwareIftypes(s) => {
                Nl80211InterfaceTypes::from(s).as_slice().emit(buffer)
            }
            Self::Features(d) => {
                buffer.copy_from_slice(&d.bits().to_ne_bytes())
            }
            Self::ExtFeatures(s) => Nl80211ExtFeatures::from(s).emit(buffer),
            Self::InterfaceCombination(s) => s.as_slice().emit(buffer),
            Self::HtCapabilityMask(s) => s.emit(buffer),
            Self::TxFrameTypes(s) => s.as_slice().emit(buffer),
            Self::RxFrameTypes(s) => s.as_slice().emit(buffer),
            Self::ExtCap(v) => v.emit(buffer),
            Self::ExtCapMask(v) => v.emit(buffer),
            Self::VhtCap(v) => v.emit(buffer),
            Self::VhtCapMask(v) => v.emit(buffer),
            Self::MaxCsaCounters(v) => buffer[0] = *v,
            Self::IfTypeExtCap(s) => {
                Nl80211IfTypeExtCapas::from(s).as_slice().emit(buffer)
            }
            Self::EmlCapability(d)
            | Self::MldCapaAndOps(d)
            | Self::MaxNumAkmSuites(d)
            | Self::MaxHwTimestampPeers(d)
            | Self::MeasurementDuration(d) => write_u16(buffer, *d),
            Self::Bands(v) => v.emit(buffer),
            Self::Bss(v) => v.as_slice().emit(buffer),
            Self::ScanSsids(v) => {
                Nla80211ScanSsidNlas::from(v).as_slice().emit(buffer)
            }
            Self::ScanFlags(v) => v.emit(buffer),
            Self::ScanFrequencies(v) => {
                Nla80211ScanFreqNlas::from(v).as_slice().emit(buffer)
            }
            Self::SchedScanMatch(v) => v.as_slice().emit(buffer),
            Self::SchedScanPlans(v) => v.as_slice().emit(buffer),
            Self::Other(attr) => attr.emit(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for Nl80211Attr {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NL80211_ATTR_IFINDEX => {
                let err_msg =
                    format!("Invalid NL80211_ATTR_IFINDEX value {payload:?}");
                Self::IfIndex(parse_u32(payload).context(err_msg)?)
            }
            NL80211_ATTR_WIPHY => {
                let err_msg =
                    format!("Invalid NL80211_ATTR_WIPHY value {payload:?}");
                Self::Wiphy(parse_u32(payload).context(err_msg)?)
            }
            NL80211_ATTR_WIPHY_NAME => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_WIPHY_NAME value {payload:?}"
                );
                Self::WiphyName(parse_string(payload).context(err_msg)?)
            }
            NL80211_ATTR_IFNAME => {
                let err_msg =
                    format!("Invalid NL80211_ATTR_IFNAME value {payload:?}");
                Self::IfName(parse_string(payload).context(err_msg)?)
            }
            NL80211_ATTR_IFTYPE => {
                Self::IfType(Nl80211InterfaceType::parse(payload)?)
            }
            NL80211_ATTR_WDEV => {
                let err_msg =
                    format!("Invalid NL80211_ATTR_WDEV value {payload:?}");
                Self::Wdev(parse_u64(payload).context(err_msg)?)
            }
            NL80211_ATTR_MAC => Self::Mac(if payload.len() == ETH_ALEN {
                let mut ret = [0u8; ETH_ALEN];
                ret.copy_from_slice(&payload[..ETH_ALEN]);
                ret
            } else {
                return Err(format!(
                    "Invalid length of NL80211_ATTR_MAC, \
                    expected length {ETH_ALEN} got {payload:?}"
                )
                .into());
            }),
            NL80211_ATTR_MAC_MASK => {
                Self::MacMask(if payload.len() == ETH_ALEN {
                    let mut ret = [0u8; ETH_ALEN];
                    ret.copy_from_slice(&payload[..ETH_ALEN]);
                    ret
                } else {
                    return Err(format!(
                        "Invalid length of NL80211_ATTR_MAC_MASK, \
                        expected length {ETH_ALEN} got {payload:?}"
                    )
                    .into());
                })
            }
            NL80211_ATTR_MAC_ADDRS => {
                Self::MacAddrs(MacAddressNlas::parse(payload)?.into())
            }
            NL80211_ATTR_GENERATION => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_GENERATION value {payload:?}"
                );
                Self::Generation(parse_u32(payload).context(err_msg)?)
            }
            NL80211_ATTR_BSS => {
                let err_msg =
                    format!("Invalid NL80211_ATTR_BSS value {payload:?}");
                let mut nlas = Vec::new();
                for nla in NlasIterator::new(payload) {
                    let nla = &nla.context(err_msg.clone())?;
                    nlas.push(Nl80211BssInfo::parse(nla)?);
                }
                Self::Bss(nlas)
            }
            NL80211_ATTR_4ADDR => {
                let err_msg =
                    format!("Invalid NL80211_ATTR_4ADDR value {payload:?}");
                Self::Use4Addr(parse_u8(payload).context(err_msg)? > 0)
            }
            NL80211_ATTR_WIPHY_FREQ => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_WIPHY_FREQ value {payload:?}"
                );
                Self::WiphyFreq(parse_u32(payload).context(err_msg)?)
            }
            NL80211_ATTR_WIPHY_FREQ_OFFSET => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_WIPHY_FREQ_OFFSET value {payload:?}"
                );
                Self::WiphyFreqOffset(parse_u32(payload).context(err_msg)?)
            }
            NL80211_ATTR_WIPHY_CHANNEL_TYPE => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_WIPHY_CHANNEL_TYPE value {payload:?}"
                );
                Self::WiphyChannelType(
                    parse_u32(payload).context(err_msg)?.into(),
                )
            }
            NL80211_ATTR_CHANNEL_WIDTH => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_CHANNEL_WIDTH value {payload:?}"
                );
                Self::ChannelWidth(parse_u32(payload).context(err_msg)?.into())
            }
            NL80211_ATTR_CENTER_FREQ1 => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_CENTER_FREQ1 value {payload:?}"
                );
                Self::CenterFreq1(parse_u32(payload).context(err_msg)?)
            }
            NL80211_ATTR_CENTER_FREQ2 => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_CENTER_FREQ2 value {payload:?}"
                );
                Self::CenterFreq2(parse_u32(payload).context(err_msg)?)
            }
            NL80211_ATTR_WIPHY_TX_POWER_LEVEL => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_WIPHY_TX_POWER_LEVEL value {payload:?}"
                );
                Self::WiphyTxPowerLevel(parse_u32(payload).context(err_msg)?)
            }
            NL80211_ATTR_SSID => {
                let err_msg =
                    format!("Invalid NL80211_ATTR_SSID value {payload:?}");
                Self::Ssid(parse_string(payload).context(err_msg)?)
            }
            NL80211_ATTR_STA_INFO => {
                let err_msg =
                    format!("Invalid NL80211_ATTR_STA_INFO value {payload:?}");
                let mut nlas = Vec::new();
                for nla in NlasIterator::new(payload) {
                    let nla = &nla.context(err_msg.clone())?;
                    nlas.push(
                        Nl80211StationInfo::parse(nla)
                            .context(err_msg.clone())?,
                    );
                }
                Self::StationInfo(nlas)
            }
            NL80211_ATTR_SURVEY_INFO => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_SURVEY_INFO value {payload:?}"
                );
                let mut nlas = Vec::new();
                for nla in NlasIterator::new(payload) {
                    let nla = &nla.context(err_msg.clone())?;
                    nlas.push(
                        Nl80211SurveyInfo::parse(nla)
                            .context(err_msg.clone())?,
                    );
                }
                Self::SurveyInfo(nlas)
            }
            NL80211_ATTR_SURVEY_RADIO_STATS => Self::SurveyRadioStats,
            NL80211_ATTR_TXQ_STATS => {
                let err_msg =
                    format!("Invalid NL80211_ATTR_TXQ_STATS value {payload:?}");
                let mut nlas = Vec::new();
                for nla in NlasIterator::new(payload) {
                    let nla = &nla.context(err_msg.clone())?;
                    nlas.push(
                        Nl80211TransmitQueueStat::parse(nla)
                            .context(err_msg.clone())?,
                    );
                }
                Self::TransmitQueueStats(nlas)
            }
            NL80211_ATTR_TXQ_LIMIT => {
                Self::TransmitQueueLimit(parse_u32(payload).context(
                    format!("Invalid NL80211_ATTR_TXQ_LIMIT {payload:?}"),
                )?)
            }
            NL80211_ATTR_TXQ_MEMORY_LIMIT => Self::TransmitQueueMemoryLimit(
                parse_u32(payload).context(format!(
                    "Invalid NL80211_ATTR_TXQ_MEMORY_LIMIT {payload:?}"
                ))?,
            ),
            NL80211_ATTR_TXQ_QUANTUM => {
                Self::TransmitQueueQuantum(parse_u32(payload).context(
                    format!("Invalid NL80211_ATTR_TXQ_QUANTUM {payload:?}"),
                )?)
            }
            NL80211_ATTR_MLO_LINKS => {
                let err_msg =
                    format!("Invalid NL80211_ATTR_MLO_LINKS value {payload:?}");
                let mut links = Vec::new();
                for nla in NlasIterator::new(payload) {
                    let nla = &nla.context(err_msg.clone())?;
                    links.push(
                        Nl80211MloLink::parse(nla).context(err_msg.clone())?,
                    );
                }
                Self::MloLinks(links)
            }
            NL80211_ATTR_WIPHY_RETRY_SHORT => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_WIPHY_RETRY_SHORT value {payload:?}"
                );
                Self::WiphyRetryShort(parse_u8(payload).context(err_msg)?)
            }
            NL80211_ATTR_WIPHY_RETRY_LONG => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_WIPHY_RETRY_LONG value {payload:?}"
                );
                Self::WiphyRetryLong(parse_u8(payload).context(err_msg)?)
            }
            NL80211_ATTR_WIPHY_FRAG_THRESHOLD => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_WIPHY_FRAG_THRESHOLD value {payload:?}"
                );
                Self::WiphyFragThreshold(parse_u32(payload).context(err_msg)?)
            }
            NL80211_ATTR_WIPHY_RTS_THRESHOLD => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_WIPHY_RTS_THRESHOLD value {payload:?}"
                );
                Self::WiphyRtsThreshold(parse_u32(payload).context(err_msg)?)
            }
            NL80211_ATTR_WIPHY_COVERAGE_CLASS => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_WIPHY_COVERAGE_CLASS value {payload:?}"
                );
                Self::WiphyCoverageClass(parse_u8(payload).context(err_msg)?)
            }
            NL80211_ATTR_MAX_NUM_SCAN_SSIDS => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_MAX_NUM_SCAN_SSIDS value {payload:?}"
                );
                Self::MaxNumScanSsids(parse_u8(payload).context(err_msg)?)
            }
            NL80211_ATTR_MAX_NUM_SCHED_SCAN_SSIDS => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_MAX_NUM_SCHED_SCAN_SSIDS value {payload:?}"
                );
                Self::MaxNumSchedScanSsids(parse_u8(payload).context(err_msg)?)
            }
            NL80211_ATTR_MAX_SCAN_IE_LEN => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_MAX_SCAN_IE_LEN value {payload:?}"
                );
                Self::MaxScanIeLen(parse_u16(payload).context(err_msg)?)
            }
            NL80211_ATTR_MAX_SCHED_SCAN_IE_LEN => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_MAX_SCHED_SCAN_IE_LEN value {payload:?}"
                );
                Self::MaxSchedScanIeLen(parse_u16(payload).context(err_msg)?)
            }
            NL80211_ATTR_MAX_MATCH_SETS => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_MAX_MATCH_SETS value {payload:?}"
                );
                Self::MaxMatchSets(parse_u8(payload).context(err_msg)?)
            }
            NL80211_ATTR_SUPPORT_IBSS_RSN => Self::SupportIbssRsn,
            NL80211_ATTR_SUPPORT_MESH_AUTH => Self::SupportMeshAuth,
            NL80211_ATTR_SUPPORT_AP_UAPSD => Self::SupportApUapsd,
            NL80211_ATTR_ROAM_SUPPORT => Self::RoamSupport,
            NL80211_ATTR_TDLS_SUPPORT => Self::TdlsSupport,
            NL80211_ATTR_TDLS_EXTERNAL_SETUP => Self::TdlsExternalSetup,
            NL80211_ATTR_CIPHER_SUITES => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_CIPHER_SUITES value {payload:?}"
                );
                let mut suits = Vec::new();
                for i in 0..(payload.len() / 4) {
                    suits.push(
                        parse_u32(&payload[i * 4..(i + 1) * 4])
                            .context(err_msg.clone())?
                            .into(),
                    );
                }
                Self::CipherSuites(suits)
            }
            NL80211_ATTR_MAX_NUM_PMKIDS => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_MAX_NUM_PMKIDS value {payload:?}"
                );
                Self::MaxNumPmkids(parse_u8(payload).context(err_msg)?)
            }
            NL80211_ATTR_CONTROL_PORT_ETHERTYPE => Self::ControlPortEthertype,
            NL80211_ATTR_WIPHY_ANTENNA_AVAIL_TX => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_WIPHY_ANTENNA_AVAIL_TX value {payload:?}"
                );
                Self::WiphyAntennaAvailTx(parse_u32(payload).context(err_msg)?)
            }
            NL80211_ATTR_WIPHY_ANTENNA_AVAIL_RX => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_WIPHY_ANTENNA_AVAIL_RX value {payload:?}"
                );
                Self::WiphyAntennaAvailRx(parse_u32(payload).context(err_msg)?)
            }
            NL80211_ATTR_PROBE_RESP_OFFLOAD => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_PROBE_RESP_OFFLOAD value {payload:?}"
                );
                Self::ApProbeRespOffload(parse_u32(payload).context(err_msg)?)
            }
            NL80211_ATTR_WIPHY_ANTENNA_TX => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_WIPHY_ANTENNA_TX value {payload:?}"
                );
                Self::WiphyAntennaTx(parse_u32(payload).context(err_msg)?)
            }
            NL80211_ATTR_WIPHY_ANTENNA_RX => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_WIPHY_ANTENNA_RX value {payload:?}"
                );
                Self::WiphyAntennaRx(parse_u32(payload).context(err_msg)?)
            }
            NL80211_ATTR_SUPPORTED_IFTYPES => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_SUPPORTED_IFTYPES value {payload:?}"
                );
                let mut nlas = Vec::new();
                for nla in NlasIterator::new(payload) {
                    let nla = &nla.context(err_msg.clone())?;
                    nlas.push(
                        Nl80211IfMode::parse(nla).context(err_msg.clone())?,
                    );
                }
                Self::SupportedIftypes(nlas)
            }
            NL80211_ATTR_WIPHY_BANDS => {
                let mut nlas = Vec::new();
                for nla in NlasIterator::new(payload) {
                    let err_msg = format!(
                        "Invalid NL80211_ATTR_WIPHY_BANDS value {nla:?}"
                    );
                    let nla = &nla.context(err_msg.clone())?;
                    nlas.push(Nl80211Band::parse(nla)?);
                }
                Self::WiphyBands(nlas)
            }
            NL80211_ATTR_SPLIT_WIPHY_DUMP => Self::SplitWiphyDump,
            NL80211_ATTR_SUPPORTED_COMMANDS => {
                Self::SupportedCommand(Nl80211Commands::parse(payload)?.into())
            }
            NL80211_ATTR_MAX_REMAIN_ON_CHANNEL_DURATION => {
                let err_msg = format!(
                    "Invalid \
                    NL80211_ATTR_MAX_REMAIN_ON_CHANNEL_DURATION {payload:?}"
                );
                Self::MaxRemainOnChannelDuration(
                    parse_u32(payload).context(err_msg)?,
                )
            }
            NL80211_ATTR_WOWLAN_TRIGGERS_SUPPORTED => {
                let mut nlas = Vec::new();
                for nla in NlasIterator::new(payload) {
                    let err_msg = format!(
                        "Invalid NL80211_ATTR_WOWLAN_TRIGGERS_SUPPORTED \
                        value {nla:?}"
                    );
                    let nla = &nla.context(err_msg.clone())?;
                    nlas.push(Nl80211WowlanTrigersSupport::parse(nla)?);
                }
                Self::WowlanTrigersSupport(nlas)
            }
            NL80211_ATTR_OFFCHANNEL_TX_OK => Self::OffchannelTxOk,
            NL80211_ATTR_SOFTWARE_IFTYPES => Self::SoftwareIftypes(
                Nl80211InterfaceTypes::parse(
                    payload,
                    "NL80211_ATTR_SOFTWARE_IFTYPES",
                )?
                .0,
            ),
            NL80211_ATTR_FEATURE_FLAGS => Self::Features(
                Nl80211Features::from_bits_retain(parse_u32(payload).context(
                    format!("Invalid NL80211_ATTR_FEATURE_FLAGS {payload:?}"),
                )?),
            ),
            NL80211_ATTR_EXT_FEATURES => {
                Self::ExtFeatures(Nl80211ExtFeatures::parse(payload)?.0)
            }
            NL80211_ATTR_INTERFACE_COMBINATIONS => {
                let mut nlas = Vec::new();
                for (index, nla) in NlasIterator::new(payload).enumerate() {
                    let err_msg = format!(
                        "Invalid NL80211_ATTR_INTERFACE_COMBINATIONS \
                        value {nla:?}"
                    );
                    let nla = &nla.context(err_msg.clone())?;
                    nlas.push(Nl80211IfaceComb::parse_with_param(
                        nla,
                        index as u16,
                    )?);
                }
                Self::InterfaceCombination(nlas)
            }
            NL80211_ATTR_HT_CAPABILITY_MASK => {
                Self::HtCapabilityMask(Nl80211HtCapabilityMask::new(payload))
            }
            NL80211_ATTR_RX_FRAME_TYPES => {
                let mut nlas = Vec::new();
                for nla in NlasIterator::new(payload) {
                    let err_msg = format!(
                        "Invalid NL80211_ATTR_RX_FRAME_TYPES value {nla:?}"
                    );
                    let nla = &nla.context(err_msg.clone())?;
                    nlas.push(Nl80211IfaceFrameType::parse(nla)?);
                }
                Self::RxFrameTypes(nlas)
            }
            NL80211_ATTR_TX_FRAME_TYPES => {
                let mut nlas = Vec::new();
                for nla in NlasIterator::new(payload) {
                    let err_msg = format!(
                        "Invalid NL80211_ATTR_RX_FRAME_TYPES value {nla:?}"
                    );
                    let nla = &nla.context(err_msg.clone())?;
                    nlas.push(Nl80211IfaceFrameType::parse(nla)?);
                }
                Self::TxFrameTypes(nlas)
            }
            NL80211_ATTR_MAX_NUM_SCHED_SCAN_PLANS => {
                Self::MaxNumSchedScanPlans(parse_u32(payload).context(
                    format!(
                        "Invalid NL80211_ATTR_MAX_NUM_SCHED_SCAN_PLANS \
                        {payload:?}"
                    ),
                )?)
            }
            NL80211_ATTR_MAX_SCAN_PLAN_INTERVAL => Self::MaxScanPlanInterval(
                parse_u32(payload).context(format!(
                    "Invalid NL80211_ATTR_MAX_SCAN_PLAN_INTERVAL \
                        {payload:?}"
                ))?,
            ),
            NL80211_ATTR_MAX_SCAN_PLAN_ITERATIONS => {
                Self::MaxScanPlanIterations(parse_u32(payload).context(
                    format!(
                        "Invalid NL80211_ATTR_MAX_SCAN_PLAN_ITERATIONS \
                        {payload:?}"
                    ),
                )?)
            }
            NL80211_ATTR_EXT_CAPA => {
                Self::ExtCap(Nl80211ExtendedCapability::new(payload))
            }
            NL80211_ATTR_EXT_CAPA_MASK => {
                Self::ExtCapMask(Nl80211ExtendedCapability::new(payload))
            }
            NL80211_ATTR_VHT_CAPABILITY => {
                Self::VhtCap(Nl80211VhtCapability::parse(payload)?)
            }
            NL80211_ATTR_VHT_CAPABILITY_MASK => {
                Self::VhtCapMask(Nl80211VhtCapability::parse(payload)?)
            }
            NL80211_ATTR_MAX_CSA_COUNTERS => {
                Self::MaxCsaCounters(parse_u8(payload).context(format!(
                    "Invalid NL80211_ATTR_MAX_CSA_COUNTERS {payload:?}"
                ))?)
            }
            NL80211_ATTR_WIPHY_SELF_MANAGED_REG => Self::WiphySelfManagedReg,
            NL80211_ATTR_SCHED_SCAN_MAX_REQS => {
                Self::SchedScanMaxReqs(parse_u32(payload).context(format!(
                    "Invalid NL80211_ATTR_SCHED_SCAN_MAX_REQS {payload:?}"
                ))?)
            }
            NL80211_ATTR_IFTYPE_EXT_CAPA => {
                Self::IfTypeExtCap(Nl80211IfTypeExtCapas::parse(buf)?.into())
            }
            NL80211_ATTR_EML_CAPABILITY => {
                Self::EmlCapability(parse_u16(payload).context(format!(
                    "Invalid NL80211_ATTR_EML_CAPABILITY {payload:?}"
                ))?)
            }
            NL80211_ATTR_MLD_CAPA_AND_OPS => {
                Self::MldCapaAndOps(parse_u16(payload).context(format!(
                    "Invalid NL80211_ATTR_MLD_CAPA_AND_OPS {payload:?}"
                ))?)
            }
            NL80211_ATTR_BANDS => {
                Self::Bands(Nl80211BandTypes::parse(payload)?)
            }
            NL80211_ATTR_MAX_NUM_AKM_SUITES => {
                Self::MaxNumAkmSuites(parse_u16(payload).context(format!(
                    "Invalid NL80211_ATTR_MAX_NUM_AKM_SUITES {payload:?}"
                ))?)
            }
            NL80211_ATTR_MAX_HW_TIMESTAMP_PEERS => Self::MaxHwTimestampPeers(
                parse_u16(payload).context(format!(
                    "Invalid NL80211_ATTR_MAX_HW_TIMESTAMP_PEERS {payload:?}"
                ))?,
            ),
            NL80211_ATTR_SCAN_SSIDS => {
                Self::ScanSsids(Nla80211ScanSsidNlas::parse(payload)?.into())
            }
            NL80211_ATTR_SCAN_FLAGS => {
                Self::ScanFlags(Nl80211ScanFlags::parse(payload)?)
            }
            NL80211_ATTR_MEASUREMENT_DURATION => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_MEASUREMENT_DURATION value {payload:?}"
                );
                Self::MeasurementDuration(parse_u16(payload).context(err_msg)?)
            }
            NL80211_ATTR_SCHED_SCAN_INTERVAL => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_SCHED_SCAN_INTERVAL value {payload:?}"
                );
                Self::SchedScanInterval(parse_u32(payload).context(err_msg)?)
            }
            NL80211_ATTR_SCHED_SCAN_DELAY => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_SCHED_SCAN_DELAY value {payload:?}"
                );
                Self::SchedScanDelay(parse_u32(payload).context(err_msg)?)
            }
            NL80211_ATTR_SCAN_FREQUENCIES => Self::ScanFrequencies(
                Nla80211ScanFreqNlas::parse(payload)?.into(),
            ),
            NL80211_ATTR_SCHED_SCAN_MATCH => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_SCHED_SCAN_MATCH value {payload:?}"
                );
                let mut nlas = Vec::new();
                for nla in NlasIterator::new(payload) {
                    let nla = &nla.context(err_msg.clone())?;
                    nlas.push(Nl80211SchedScanMatch::parse(nla)?);
                }
                Self::SchedScanMatch(nlas)
            }
            NL80211_ATTR_SCHED_SCAN_PLANS => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_SCHED_SCAN_PLANS value {payload:?}"
                );
                let mut nlas = Vec::new();
                for nla in NlasIterator::new(payload) {
                    let nla = &nla.context(err_msg.clone())?;
                    nlas.push(Nl80211SchedScanPlan::parse(nla)?);
                }
                Self::SchedScanPlans(nlas)
            }
            _ => Self::Other(
                DefaultNla::parse(buf).context("invalid NLA (unknown kind)")?,
            ),
        })
    }
}
