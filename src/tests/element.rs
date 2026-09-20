// SPDX-License-Identifier: MIT

use netlink_packet_core::{Emitable, Parseable};

use crate::element::{Ieee80211ElementCountry, Ieee80211ElementSubBand};
use crate::{
    ap_rsne_supports_ext_key_id, ap_rsne_supports_ocv,
    ap_rsnxe_supports_sae_h2e, ap_supports_btm, ap_supports_rm_neighbor_report,
    find_ie, find_ie_pos, ft_psk_ie_cipher, ft_sae_ie_cipher,
    ftie_auth_request, ie_at, mdie, parse_ftie, parse_group_mgmt_cipher,
    parse_mdie, rsne_first_pmkid, rsne_match_ignore_pmkid, rsne_set_ext_key_id,
    rsne_set_ocvc, sae_ie_cipher, sae_rsnxe, wpa2_ent_ie_cipher,
    wpa2_ent_sha256_ie_cipher, wpa2_psk_ie_with_pmkid_cipher,
    Ieee80211AkmSuite, Ieee80211CipherSuite, Ieee80211Element,
    Ieee80211ElementBuffer, Ieee80211ElementCountryEnvironment,
    Ieee80211ElementCountryTriplet, Ieee80211ElementRsn,
    Ieee80211ElementRsnExt, Ieee80211RateAndSelector, Ieee80211RsnCapbilities,
    Ieee80211RsnExtCapbilities, ELEMENT_ID_EXTENSION, ELEMENT_ID_EXT_CAPAB,
    ELEMENT_ID_FTIE, ELEMENT_ID_MDIE, ELEMENT_ID_RM_ENABLED_CAPAB,
    ELEMENT_ID_RSN,
};

#[test]
fn ssid() {
    // The string variant is only for building, the parser stores the SSID
    // octets raw.
    let val: Ieee80211Element = Ieee80211Element::Ssid("test-ssid".to_owned());
    let mut buffer = vec![0; val.buffer_len() + 1];
    val.emit(buffer.as_mut_slice());
    assert_eq!(
        <Ieee80211Element>::parse(&buffer[0..val.buffer_len()]).unwrap(),
        Ieee80211Element::SsidRaw(b"test-ssid".to_vec()),
    );
}

#[test]
fn rates_and_selectors() {
    let val: Ieee80211Element =
        Ieee80211Element::SupportedRatesAndSelectors(vec![
            Ieee80211RateAndSelector::BssBasicRateSet(1),
            Ieee80211RateAndSelector::Rate(1),
            Ieee80211RateAndSelector::SelectorHt,
            Ieee80211RateAndSelector::SelectorVht,
            Ieee80211RateAndSelector::SelectorGlk,
            Ieee80211RateAndSelector::SelectorEht,
        ]);
    let mut buffer = vec![0; val.buffer_len() + 1];
    val.emit(buffer.as_mut_slice());
    assert_eq!(
        <Ieee80211Element>::parse(&buffer[0..val.buffer_len()]).unwrap(),
        val,
    );
}

#[test]
fn channel() {
    let val: Ieee80211Element = Ieee80211Element::Channel(7);
    let mut buffer = vec![0; val.buffer_len() + 1];
    val.emit(buffer.as_mut_slice());
    assert_eq!(
        <Ieee80211Element>::parse(&buffer[0..val.buffer_len()]).unwrap(),
        val,
    );
}

#[test]
fn country() {
    let val: Ieee80211Element =
        Ieee80211Element::Country(Ieee80211ElementCountry {
            country: "DE".to_owned(),
            environment: Ieee80211ElementCountryEnvironment::IndoorAndOutdoor,
            triplets: vec![Ieee80211ElementCountryTriplet::Subband(
                Ieee80211ElementSubBand {
                    channel_start: 1,
                    channel_count: 13,
                    max_power_level: 20,
                },
            )],
        });
    let mut buffer = vec![0; val.buffer_len() + 1];
    val.emit(buffer.as_mut_slice());
    assert_eq!(
        <Ieee80211Element>::parse(&buffer[0..val.buffer_len()]).unwrap(),
        val,
    );
}

#[test]
fn rsn() {
    let val: Ieee80211Element = Ieee80211Element::Rsn(Ieee80211ElementRsn {
        version: 1,
        group_cipher: Some(Ieee80211CipherSuite::Ccmp128),
        pairwise_ciphers: vec![Ieee80211CipherSuite::Ccmp128],
        akm_suits: vec![Ieee80211AkmSuite::Psk],
        rsn_capbilities: None,
        pmkids: Vec::new(),
        group_mgmt_cipher: None,
    });
    let mut buffer = vec![0; val.buffer_len() + 1];
    val.emit(buffer.as_mut_slice());
    assert_eq!(
        <Ieee80211Element>::parse(&buffer[0..val.buffer_len()]).unwrap(),
        val,
    );
}

// Extended RSN Capabilities element (RSNXE) advertising SAE Hash-to-Element.
// `f4 01 20` was captured from a hostapd WPA3 AP's beacon on an nlmon monitor:
// element id 244, length 1, value 0x20 (Field length subfield 0, SAE-H2E bit).
#[test]
fn rsn_ext_sae_h2e_captured() {
    let raw = vec![0xf4, 0x01, 0x20];
    let val = Ieee80211Element::RsnExt(Ieee80211ElementRsnExt {
        capabilities: Ieee80211RsnExtCapbilities::SaeH2e,
    });
    let mut buffer = vec![0; val.buffer_len()];
    val.emit(buffer.as_mut_slice());
    assert_eq!(buffer, raw);
    assert_eq!(<Ieee80211Element>::parse(&raw).unwrap(), val);
}

#[test]
fn rsn_ext_multi_octet() {
    // SsidProtection is bit 21 -> requires a 3-octet field (Field length 2).
    let val = Ieee80211Element::RsnExt(Ieee80211ElementRsnExt {
        capabilities: Ieee80211RsnExtCapbilities::SaeH2e
            | Ieee80211RsnExtCapbilities::SsidProtection,
    });
    // id, len=3, then field: octet0 = len-nibble(2) | SAE-H2E(0x20) = 0x22,
    // octet1 = 0, octet2 = bit21 = 0x20.
    assert_eq!(
        {
            let mut b = vec![0; val.buffer_len()];
            val.emit(b.as_mut_slice());
            b
        },
        vec![0xf4, 0x03, 0x22, 0x00, 0x20],
    );
    let raw = vec![0xf4, 0x03, 0x22, 0x00, 0x20];
    assert_eq!(<Ieee80211Element>::parse(&raw).unwrap(), val);
}

// A capability bit beyond the u32 range (a 5-octet field with a bit in the
// 5th octet) must round-trip, exercising the u128 backing storage. The Field
// length subfield is 4 (n - 1 = 5 - 1).
#[test]
fn rsn_ext_beyond_u32() {
    let raw = vec![0xf4, 0x05, 0x04, 0x00, 0x00, 0x00, 0x80];
    let val = <Ieee80211Element>::parse(&raw).unwrap();
    let mut buffer = vec![0; val.buffer_len()];
    val.emit(buffer.as_mut_slice());
    assert_eq!(buffer, raw);
}

// The Field length subfield (low nibble of the first octet) is authoritative:
// trailing bytes beyond it must not be parsed as extra capability bits. Here
// the subfield says n = 1 (one octet, SAE-H2E) but a stray 0xff trails it.
#[test]
fn rsn_ext_ignores_trailing_bytes() {
    let payload = vec![0x20, 0xff];
    let parsed = Ieee80211ElementRsnExt::parse(&payload).unwrap();
    assert_eq!(
        parsed.capabilities,
        Ieee80211RsnExtCapbilities::SaeH2e,
        "trailing 0xff beyond the field length must be ignored"
    );
}

/// Decode a full RSNE element (ID + length + body) with the typed RSN
/// model.
fn parse_ie(ie: &[u8]) -> Ieee80211ElementRsn {
    let len = ie[1] as usize;
    Ieee80211ElementRsn::parse(&ie[2..len + 2]).expect("valid RSNE")
}

/// Build an IE buffer from (id, body) pairs.
fn ies(parts: &[(u8, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (id, body) in parts {
        out.push(*id);
        out.push(body.len() as u8);
        out.extend_from_slice(body);
    }
    out
}

#[test]
fn test_find_ie() {
    let buf = ies(&[
        (ELEMENT_ID_RSN, &[0x01, 0x00]),
        (ELEMENT_ID_MDIE, &[0x02, 0x03, 0x00]),
    ]);
    assert_eq!(find_ie(&buf, ELEMENT_ID_RSN), Some(&buf[2..4]));
    assert_eq!(find_ie(&buf, ELEMENT_ID_MDIE), Some(&buf[6..9]));
    assert_eq!(find_ie(&buf, ELEMENT_ID_EXT_CAPAB), None);

    let pos = find_ie_pos(&buf, ELEMENT_ID_MDIE).expect("MDIE position");
    assert_eq!(pos, 4);
    assert_eq!(ie_at(&buf, pos), &buf[4..9]);

    // A truncated element ends the search instead of panicking.
    assert_eq!(find_ie(&buf[..5], ELEMENT_ID_MDIE), None);
    assert_eq!(find_ie(&[], ELEMENT_ID_RSN), None);
}

/// The element header is a two-octet zerocopy struct: only the Length
/// octets that follow it belong to the element, so the next element of an
/// information element buffer is never read as part of its body.
#[test]
fn test_element_buffer_split() {
    let buf = ies(&[
        (ELEMENT_ID_RSN, &[0x01, 0x00]),
        (ELEMENT_ID_MDIE, &[0x02, 0x03, 0x00]),
    ]);
    let (header, body) = Ieee80211ElementBuffer::split(&buf).unwrap();
    assert_eq!(*header, Ieee80211ElementBuffer::new(ELEMENT_ID_RSN, 2));
    assert_eq!(header.buffer_len(), 4);
    assert_eq!(body, &[0x01, 0x00]);

    // An element with an empty body is still an element.
    let (header, body) = Ieee80211ElementBuffer::split(&[73, 0]).unwrap();
    assert_eq!(*header, Ieee80211ElementBuffer::new(73, 0));
    assert_eq!(header.buffer_len(), 2);
    assert!(body.is_empty());

    // An element that is not complete is refused instead of reading the
    // octets that follow it.
    assert!(Ieee80211ElementBuffer::split(&[]).is_err());
    assert!(Ieee80211ElementBuffer::split(&[ELEMENT_ID_RSN]).is_err());
    assert!(Ieee80211ElementBuffer::split(&buf[..3]).is_err());
}

/// Extensible elements (Element ID 255) carry the Element ID Extension as
/// their first body octet; other elements do not have one.
#[test]
fn test_element_buffer_element_id_ext() {
    // Extension ID 35 is the HE Capabilities element.
    let he = ies(&[(ELEMENT_ID_EXTENSION, &[35, 0x11])]);
    let (header, body) = Ieee80211ElementBuffer::split(&he).unwrap();
    assert!(header.has_element_id_ext());
    assert_eq!(header.element_id_ext(body), Some(35));
    // An extensible element without the Element ID Extension field has no
    // extension ID to report.
    assert_eq!(header.element_id_ext(&[]), None);

    let rsne = ies(&[(ELEMENT_ID_RSN, &[0x01, 0x00])]);
    let (header, body) = Ieee80211ElementBuffer::split(&rsne).unwrap();
    assert!(!header.has_element_id_ext());
    assert_eq!(header.element_id_ext(body), None);
}

/// An element buffer too short for its header or for the body its Length
/// field promises is refused, not sliced out of bounds.
#[test]
fn test_element_parse_truncated() {
    let buf = ies(&[(ELEMENT_ID_RSN, &[0x01, 0x00])]);
    assert!(<Ieee80211Element>::parse(&[]).is_err());
    assert!(<Ieee80211Element>::parse(&[ELEMENT_ID_RSN]).is_err());
    assert!(<Ieee80211Element>::parse(&buf[..3]).is_err());
    assert!(<Ieee80211Element>::parse(&buf).is_ok());
}

#[test]
fn test_ap_supports_btm() {
    // Bit 19 of the Extended Capabilities element: octet 2, bit 3.
    let btm = ies(&[(ELEMENT_ID_EXT_CAPAB, &[0x00, 0x00, 0x08])]);
    assert!(ap_supports_btm(&btm));

    // Other bits of the same octet do not advertise BTM.
    let no_btm = ies(&[(ELEMENT_ID_EXT_CAPAB, &[0x00, 0x00, 0x10])]);
    assert!(!ap_supports_btm(&no_btm));

    // Element too short for bit 19.
    let short = ies(&[(ELEMENT_ID_EXT_CAPAB, &[0x00, 0x00])]);
    assert!(!ap_supports_btm(&short));

    // No Extended Capabilities element at all.
    assert!(!ap_supports_btm(&[]));
    assert!(!ap_supports_btm(&ies(&[(ELEMENT_ID_RSN, &[0x01])])));
}

#[test]
fn test_ap_supports_rm_neighbor_report() {
    // Bit 1 of octet 0 of the RM Enabled Capabilities element.
    let nr =
        ies(&[(ELEMENT_ID_RM_ENABLED_CAPAB, &[0x02, 0x00, 0x00, 0x00, 0x00])]);
    assert!(ap_supports_rm_neighbor_report(&nr));

    // Only the link measurement bit set.
    let lm =
        ies(&[(ELEMENT_ID_RM_ENABLED_CAPAB, &[0x01, 0x00, 0x00, 0x00, 0x00])]);
    assert!(!ap_supports_rm_neighbor_report(&lm));

    // Missing element.
    assert!(!ap_supports_rm_neighbor_report(&[]));
}

#[test]
fn test_wpa3_enterprise_rsne_requires_mfp() {
    // WPA3-Enterprise (AKM 5): MFPR + MFPC both set.
    let ie = wpa2_ent_sha256_ie_cipher(Ieee80211CipherSuite::BipCmac128);
    let rsne = parse_ie(&ie);
    assert_eq!(rsne.akm_suits, vec![Ieee80211AkmSuite::Ieee8021xSha256]);
    let capab = rsne.rsn_capbilities.expect("RSN capabilities");
    assert!(
        capab.contains(Ieee80211RsnCapbilities::Mfpr),
        "MFPR must be set"
    );
    assert!(
        capab.contains(Ieee80211RsnCapbilities::Mfpc),
        "MFPC must be set"
    );
}

#[test]
fn test_wpa2_enterprise_rsne_keeps_pmf_optional() {
    // WPA2-Enterprise (AKM 1): MFPC only - PMF optional.
    let ie = wpa2_ent_ie_cipher(Ieee80211CipherSuite::BipCmac128);
    let rsne = parse_ie(&ie);
    assert_eq!(rsne.akm_suits, vec![Ieee80211AkmSuite::Ieee8021x]);
    let capab = rsne.rsn_capbilities.expect("RSN capabilities");
    assert!(
        !capab.contains(Ieee80211RsnCapbilities::Mfpr),
        "AKM 1 must not require PMF"
    );
    assert!(
        capab.contains(Ieee80211RsnCapbilities::Mfpc),
        "AKM 1 offers PMF (MFPC)"
    );
}

/// The negotiated group management (BIP) cipher is parsed back from
/// built RSNEs, with and without a PMKID in front of it.
#[test]
fn test_group_mgmt_cipher_roundtrip() {
    let gmac256 = wpa2_ent_sha256_ie_cipher(Ieee80211CipherSuite::BipGmac256);
    assert_eq!(
        parse_group_mgmt_cipher(&gmac256),
        Some(Ieee80211CipherSuite::BipGmac256)
    );

    let cmac256 = wpa2_psk_ie_with_pmkid_cipher(
        Some([0xAB; 16]),
        Ieee80211CipherSuite::BipCmac256,
    );
    assert_eq!(
        parse_group_mgmt_cipher(&cmac256),
        Some(Ieee80211CipherSuite::BipCmac256),
        "the PMKID list must be skipped before the group mgmt cipher"
    );
    // A truncated element is not an RSNE with a group management
    // cipher.
    assert_eq!(parse_group_mgmt_cipher(&[]), None);
    assert_eq!(parse_group_mgmt_cipher(&gmac256[..4]), None);
    assert_eq!(parse_group_mgmt_cipher(&sae_rsnxe()), None);
}

#[test]
fn test_ext_key_id_rsne_bit() {
    let mut ie = wpa2_ent_sha256_ie_cipher(Ieee80211CipherSuite::BipCmac128);
    rsne_set_ext_key_id(&mut ie, true);
    assert!(ap_rsne_supports_ext_key_id(&ie));
    rsne_set_ext_key_id(&mut ie, false);
    assert!(!ap_rsne_supports_ext_key_id(&ie));
}

/// The OCV capability bit (bit 14) can be set and cleared on a built
/// RSNE; a non-OCV AP is reported as such.
#[test]
fn test_ocv_rsne_bit() {
    let mut ie = wpa2_ent_sha256_ie_cipher(Ieee80211CipherSuite::BipCmac128);
    assert!(!ap_rsne_supports_ocv(&ie));
    rsne_set_ocvc(&mut ie, true);
    assert!(ap_rsne_supports_ocv(&ie));
    rsne_set_ocvc(&mut ie, false);
    assert!(!ap_rsne_supports_ocv(&ie));
}

/// The RSNE helpers read the body the Length octet promises: an element
/// whose Length stops before its RSN capabilities must not have the octets
/// that follow it read as capabilities or as the group management cipher.
#[test]
fn test_rsne_helpers_honour_element_length() {
    let mut ie = wpa2_ent_sha256_ie_cipher(Ieee80211CipherSuite::BipCmac128);
    rsne_set_ocvc(&mut ie, true);
    assert!(ap_rsne_supports_ocv(&ie));
    assert_eq!(
        parse_group_mgmt_cipher(&ie),
        Some(Ieee80211CipherSuite::BipCmac128)
    );

    // 19 octets end inside the RSN capabilities field, one octet short of
    // a complete pair, and before the group management cipher.
    ie[1] = 19;
    assert!(!ap_rsne_supports_ocv(&ie));
    assert_eq!(parse_group_mgmt_cipher(&ie), None);
}

/// An RSNE without RSN capabilities (or a malformed element) is left
/// untouched instead of panicking.
#[test]
fn test_rsne_capability_set_skips_unsupported_ie() {
    let mut ie = vec![0x30, 0x02, 0x01, 0x00];
    let orig = ie.clone();
    rsne_set_ocvc(&mut ie, true);
    rsne_set_ext_key_id(&mut ie, true);
    assert_eq!(ie, orig);
}

/// The SAE builders append the RSNXE to the RSNE; setting the OCV or
/// Extended Key ID capability must patch the RSNE in place and leave
/// the RSNXE untouched.
#[test]
fn test_rsne_capability_set_keeps_following_rsnxe() {
    let mut ie = sae_ie_cipher(Ieee80211CipherSuite::BipCmac128);
    let rsnxe = sae_rsnxe();
    let rsne_len = ie[1] as usize + 2;
    assert_eq!(&ie[rsne_len..], rsnxe.as_slice());
    assert!(!ap_rsne_supports_ocv(&ie));
    assert!(!ap_rsne_supports_ext_key_id(&ie));

    rsne_set_ocvc(&mut ie, true);
    rsne_set_ext_key_id(&mut ie, true);

    assert_eq!(ie[1] as usize + 2, rsne_len, "RSNE length must not change");
    assert_eq!(
        &ie[rsne_len..],
        rsnxe.as_slice(),
        "the RSNXE after the RSNE must not change"
    );
    assert!(ap_rsne_supports_ocv(&ie));
    assert!(ap_rsne_supports_ext_key_id(&ie));

    rsne_set_ocvc(&mut ie, false);
    assert!(!ap_rsne_supports_ocv(&ie));
    assert_eq!(&ie[rsne_len..], rsnxe.as_slice());
}

#[test]
fn test_rsne_first_pmkid_reads_pmkid_list() {
    let no_pmkid = wpa2_ent_ie_cipher(Ieee80211CipherSuite::BipCmac128);
    assert_eq!(rsne_first_pmkid(&no_pmkid[2..]), None);

    let pmkid = [0x11u8; 16];
    let with_pmkid = wpa2_psk_ie_with_pmkid_cipher(
        Some(pmkid),
        Ieee80211CipherSuite::BipCmac128,
    );
    assert_eq!(rsne_first_pmkid(&with_pmkid[2..]), Some(pmkid));
}

/// FT (Re)Association Responses carry PMKR0Name / PMKR1Name as the
/// RSNE's PMKID; that must not count as an RSNE downgrade while a
/// changed cipher suite must.
#[test]
fn test_rsne_match_ignores_pmkid() {
    let with_pmkid = |byte: u8| {
        wpa2_psk_ie_with_pmkid_cipher(
            Some([byte; 16]),
            Ieee80211CipherSuite::BipCmac128,
        )
    };
    assert!(rsne_match_ignore_pmkid(
        &with_pmkid(0xAA),
        &with_pmkid(0xAA)
    ));
    assert!(rsne_match_ignore_pmkid(
        &with_pmkid(0xAA),
        &with_pmkid(0xBB)
    ));
    // A bare RSNE body compares like the full element.
    assert!(rsne_match_ignore_pmkid(
        &with_pmkid(0xAA)[2..],
        &with_pmkid(0xBB)
    ));

    let other_akm = wpa2_ent_sha256_ie_cipher(Ieee80211CipherSuite::BipCmac128);
    assert!(!rsne_match_ignore_pmkid(&with_pmkid(0xAA), &other_akm));
}

/// The SAE RSNE + RSNXE pair advertises SAE with MFP required and the
/// SAE Hash-to-Element capability in the RSNXE.
#[test]
fn test_sae_ie_carries_rsnxe() {
    let ie = sae_ie_cipher(Ieee80211CipherSuite::BipCmac128);
    let rsne = parse_ie(&ie);
    assert_eq!(rsne.akm_suits, vec![Ieee80211AkmSuite::Sae]);
    let capab = rsne.rsn_capbilities.expect("RSN capabilities");
    assert!(capab.contains(Ieee80211RsnCapbilities::Mfpr));
    assert_eq!(sae_rsnxe().as_slice(), &ie[ie.len() - 3..]);
    assert!(ap_rsnxe_supports_sae_h2e(&ie[ie.len() - 3..]));
}

/// The FT RSNE builders carry the FT AKMs and the PMKR0Name /
/// PMKR1Name in the PMKID field.
#[test]
fn test_ft_ie_builders() {
    let pmkid = [0x5A; 16];
    let ft_sae =
        ft_sae_ie_cipher(Some(pmkid), Ieee80211CipherSuite::BipCmac128);
    let rsne = parse_ie(&ft_sae);
    assert_eq!(rsne.akm_suits, vec![Ieee80211AkmSuite::FtSae]);
    assert_eq!(rsne_first_pmkid(&ft_sae[2..]), Some(pmkid));

    let ft_psk =
        ft_psk_ie_cipher(Some(pmkid), Ieee80211CipherSuite::BipCmac128);
    let rsne = parse_ie(&ft_psk);
    assert_eq!(rsne.akm_suits, vec![Ieee80211AkmSuite::FtPsk]);
    // FT-PSK keeps PMF optional.
    let capab = rsne.rsn_capbilities.expect("RSN capabilities");
    assert!(!capab.contains(Ieee80211RsnCapbilities::Mfpr));
}

/// The MDIE builder and parser are inverses.
#[test]
fn test_mdie_roundtrip() {
    let elem = mdie([0x02, 0x03], 0x04);
    assert_eq!(elem, vec![ELEMENT_ID_MDIE, 3, 0x02, 0x03, 0x04]);
    assert_eq!(parse_mdie(&elem[2..]), Some(([0x02, 0x03], 0x04)));
    assert_eq!(parse_mdie(&[0x02]), None);
}

/// The over-the-air FT Authentication request FTIE carries a zeroed MIC
/// and ANonce, the SNonce and the R0KH-ID subelement.
#[test]
fn test_ftie_auth_request_roundtrip() {
    let snonce = [0x11u8; 32];
    let r0kh_id = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06];
    let elem = ftie_auth_request(&snonce, &r0kh_id);
    assert_eq!(elem[0], ELEMENT_ID_FTIE);

    let ftie = parse_ftie(&elem[2..]).expect("parse FTIE");
    assert_eq!(ftie.mic, [0u8; 16]);
    assert_eq!(ftie.anonce, [0u8; 32]);
    assert_eq!(ftie.snonce, snonce);
    assert_eq!(ftie.r0kh_id.as_deref(), Some(r0kh_id.as_slice()));
    assert_eq!(ftie.r1kh_id, None);
    assert_eq!(ftie.gtk, None);

    // An FTIE shorter than the fixed part is rejected.
    assert_eq!(parse_ftie(&[]), None);
}
