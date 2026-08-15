// SPDX-License-Identifier: MIT

use super::{
    Emitable, Ieee80211ElementHtCap, Ieee80211HtAMpduPara, Ieee80211HtAselCaps,
    Ieee80211HtCaps, Ieee80211HtExtendedCap, Ieee80211HtMcsInfo,
    Ieee80211HtTransmitBeamformingCaps, Ieee80211HtTxParameter,
    Nl80211HtWiphyChannelType, Parseable, IEEE80211_HT_MCS_MASK_LEN,
    NL80211_CHAN_HT40PLUS,
};

#[test]
fn caps() {
    let val: Ieee80211HtCaps = Ieee80211HtCaps::all();
    let mut buffer = vec![0; val.buffer_len() + 1];
    val.emit(buffer.as_mut_slice());
    assert_eq!(
        <Ieee80211HtCaps>::parse(&buffer[0..val.buffer_len()]).unwrap(),
        val,
    );
}

#[test]
fn asel_caps() {
    let val: Ieee80211HtAselCaps = Ieee80211HtAselCaps::all();
    let mut buffer = vec![0; val.buffer_len() + 1];
    val.emit(buffer.as_mut_slice());
    assert_eq!(
        <Ieee80211HtAselCaps>::parse(&buffer[0..val.buffer_len()]).unwrap(),
        val,
    );
}

#[test]
fn transmit_beamforming_cap() {
    let val: Ieee80211HtTransmitBeamformingCaps =
        Ieee80211HtTransmitBeamformingCaps::all();
    let mut buffer = vec![0; val.buffer_len() + 1];
    val.emit(buffer.as_mut_slice());
    assert_eq!(
        <Ieee80211HtTransmitBeamformingCaps>::parse(
            &buffer[0..val.buffer_len()]
        )
        .unwrap(),
        val,
    );
}

#[test]
fn tx_params() {
    let val: Ieee80211HtTxParameter = Ieee80211HtTxParameter {
        mcs_set_defined: false,
        tx_rx_mcs_set_not_equal: false,
        max_spatial_streams: 1,
        unequal_modulation_supported: false,
    };
    let into: u8 = val.into();
    assert_eq!(<Ieee80211HtTxParameter>::from(into), val,);
}

#[test]
fn ht_wiphy_no_ht() {
    let val: Nl80211HtWiphyChannelType = Nl80211HtWiphyChannelType::NoHt;
    let into: u32 = val.into();
    assert_eq!(<Nl80211HtWiphyChannelType>::from(into), val,);
}

#[test]
fn ht_wiphy_ht_20() {
    let val: Nl80211HtWiphyChannelType = Nl80211HtWiphyChannelType::Ht20;
    let into: u32 = val.into();
    assert_eq!(<Nl80211HtWiphyChannelType>::from(into), val,);
}

#[test]
fn ht_wiphy_other() {
    let val: Nl80211HtWiphyChannelType =
        Nl80211HtWiphyChannelType::Other(NL80211_CHAN_HT40PLUS + 1);
    let into: u32 = val.into();
    assert_eq!(<Nl80211HtWiphyChannelType>::from(into), val,);
}

#[test]
fn mcs_info() {
    let val: Ieee80211HtMcsInfo = Ieee80211HtMcsInfo {
        rx_mask: [0xA5; IEEE80211_HT_MCS_MASK_LEN],
        rx_highest: u16::MAX,
        tx_params: Ieee80211HtTxParameter {
            mcs_set_defined: false,
            tx_rx_mcs_set_not_equal: false,
            max_spatial_streams: 1,
            unequal_modulation_supported: false,
        },
    };
    let mut buffer = vec![0; val.buffer_len() + 1];
    val.emit(buffer.as_mut_slice());
    assert_eq!(
        <Ieee80211HtMcsInfo>::parse(&buffer[0..val.buffer_len()]).unwrap(),
        val,
    );
}

#[test]
fn a_mpdu_para() {
    let val: Ieee80211HtAMpduPara = Ieee80211HtAMpduPara {
        max_len_exponent: 0b11,
        min_space: 0b111,
    };
    let into: u8 = val.into();
    assert_eq!(<Ieee80211HtAMpduPara>::from(into), val,);
}

#[test]
fn extend_cap() {
    let val: Ieee80211HtExtendedCap = Ieee80211HtExtendedCap {
        pco: true,
        pco_trans_time: 1,
        mcs_feedback: 1,
        support_ht_control: true,
        rd_responder: true,
    };
    let into: [u8; 2] = val.into();
    assert_eq!(into, [0b0000_0011, 0b0000_1101]);
    assert_eq!(<Ieee80211HtExtendedCap>::from(into), val,);
}

#[test]
fn cap_mask() {
    let val: Ieee80211ElementHtCap = Ieee80211ElementHtCap {
        caps: Ieee80211HtCaps::all(),
        a_mpdu_para: Ieee80211HtAMpduPara {
            max_len_exponent: 3,
            min_space: 7,
        },
        mcs_set: Ieee80211HtMcsInfo {
            rx_mask: [0xA5; IEEE80211_HT_MCS_MASK_LEN],
            rx_highest: u16::MAX,
            tx_params: Ieee80211HtTxParameter {
                mcs_set_defined: false,
                tx_rx_mcs_set_not_equal: false,
                max_spatial_streams: 1,
                unequal_modulation_supported: false,
            },
        },
        ht_ext_cap: Ieee80211HtExtendedCap {
            pco: true,
            pco_trans_time: 2,
            mcs_feedback: 2,
            support_ht_control: true,
            rd_responder: true,
        },
        transmit_beamforming_cap: Ieee80211HtTransmitBeamformingCaps::all(),
        asel_cap: Ieee80211HtAselCaps::all(),
    };
    let mut buffer = vec![0; val.buffer_len() + 1];
    val.emit(buffer.as_mut_slice());
    assert_eq!(
        <Ieee80211ElementHtCap>::parse(&buffer[0..val.buffer_len()]).unwrap(),
        val,
    );
}
