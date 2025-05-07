// SPDX-License-Identifier: MIT

use super::{
    Emitable, Nl80211ElementHtCap, Nl80211HtAMpduPara, Nl80211HtAselCaps,
    Nl80211HtCaps, Nl80211HtExtendedCap, Nl80211HtMcsInfo,
    Nl80211HtTransmitBeamformingCaps, Nl80211HtTxParameter,
    Nl80211HtWiphyChannelType, Parseable, IEEE80211_HT_MCS_MASK_LEN,
    NL80211_CHAN_HT40PLUS,
};

#[test]
fn caps() {
    let val: Nl80211HtCaps = Nl80211HtCaps::all();
    let mut buffer = vec![0; val.buffer_len() + 1];
    val.emit(buffer.as_mut_slice());
    assert_eq!(
        <Nl80211HtCaps>::parse(&buffer[0..val.buffer_len()]).unwrap(),
        val,
    );
}

#[test]
fn asel_caps() {
    let val: Nl80211HtAselCaps = Nl80211HtAselCaps::all();
    let mut buffer = vec![0; val.buffer_len() + 1];
    val.emit(buffer.as_mut_slice());
    assert_eq!(
        <Nl80211HtAselCaps>::parse(&buffer[0..val.buffer_len()]).unwrap(),
        val,
    );
}

#[test]
fn transmit_beamforming_cap() {
    let val: Nl80211HtTransmitBeamformingCaps =
        Nl80211HtTransmitBeamformingCaps::all();
    let mut buffer = vec![0; val.buffer_len() + 1];
    val.emit(buffer.as_mut_slice());
    assert_eq!(
        <Nl80211HtTransmitBeamformingCaps>::parse(&buffer[0..val.buffer_len()])
            .unwrap(),
        val,
    );
}

#[test]
fn tx_params() {
    let val: Nl80211HtTxParameter = Nl80211HtTxParameter {
        mcs_set_defined: false,
        tx_rx_mcs_set_not_equal: false,
        max_spatial_streams: 1,
        unequal_modulation_supported: false,
    };
    let into: u8 = val.into();
    assert_eq!(<Nl80211HtTxParameter>::from(into), val,);
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
    let val: Nl80211HtMcsInfo = Nl80211HtMcsInfo {
        rx_mask: [0xA5; IEEE80211_HT_MCS_MASK_LEN],
        rx_highest: u16::MAX,
        tx_params: Nl80211HtTxParameter {
            mcs_set_defined: false,
            tx_rx_mcs_set_not_equal: false,
            max_spatial_streams: 1,
            unequal_modulation_supported: false,
        },
    };
    let mut buffer = vec![0; val.buffer_len() + 1];
    val.emit(buffer.as_mut_slice());
    assert_eq!(
        <Nl80211HtMcsInfo>::parse(&buffer[0..val.buffer_len()]).unwrap(),
        val,
    );
}

#[test]
fn a_mpdu_para() {
    let val: Nl80211HtAMpduPara = Nl80211HtAMpduPara {
        max_len_exponent: u8::MAX & 0b11,
        min_space: u8::MAX & 0b111,
    };
    let into: u8 = val.into();
    assert_eq!(<Nl80211HtAMpduPara>::from(into), val,);
}

#[test]
fn extend_cap() {
    let val: Nl80211HtExtendedCap = Nl80211HtExtendedCap {
        pco: true,
        pco_trans_time: 1,
        mcs_feedback: 1,
        support_ht_control: true,
        rd_responder: true,
    };
    let into: [u8; 2] = val.into();
    assert_eq!(<Nl80211HtExtendedCap>::from(into), val,);
}

#[test]
fn cap_mask() {
    let val: Nl80211ElementHtCap = Nl80211ElementHtCap {
        caps: Nl80211HtCaps::all(),
        a_mpdu_para: Nl80211HtAMpduPara {
            max_len_exponent: 3,
            min_space: 7,
        },
        mcs_set: Nl80211HtMcsInfo {
            rx_mask: [0xA5; IEEE80211_HT_MCS_MASK_LEN],
            rx_highest: u16::MAX,
            tx_params: Nl80211HtTxParameter {
                mcs_set_defined: false,
                tx_rx_mcs_set_not_equal: false,
                max_spatial_streams: 1,
                unequal_modulation_supported: false,
            },
        },
        ht_ext_cap: Nl80211HtExtendedCap {
            pco: true,
            pco_trans_time: 2,
            mcs_feedback: 2,
            support_ht_control: true,
            rd_responder: true,
        },
        transmit_beamforming_cap: Nl80211HtTransmitBeamformingCaps::all(),
        asel_cap: Nl80211HtAselCaps::all(),
    };
    let mut buffer = vec![0; val.buffer_len() + 1];
    val.emit(buffer.as_mut_slice());
    assert_eq!(
        <Nl80211ElementHtCap>::parse(&buffer[0..val.buffer_len()]).unwrap(),
        val,
    );
}
