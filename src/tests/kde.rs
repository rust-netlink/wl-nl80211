// SPDX-License-Identifier: MIT

use crate::{
    build_oci_kde, parse_gtk_kde, parse_key_data_kdes, parse_oci_kde,
    Ieee80211Oci, Ieee80211OciBuffer, Ieee80211OciKeyDataElemBuffer,
    ELEMENT_ID_RSN,
};

/// Build an IGTK / BIGTK KDE: OUI(3) type(1) KeyID(2 LE) IPN(6) Key(16).
fn build_mgmt_key_kde(
    kde_type: u8,
    key_id: u16,
    ipn: &[u8; 6],
    key: &[u8; 16],
) -> Vec<u8> {
    let mut kde = vec![0xDD, 4 + 2 + 6 + 16, 0x00, 0x0F, 0xAC, kde_type];
    kde.extend_from_slice(&key_id.to_le_bytes());
    kde.extend_from_slice(ipn);
    kde.extend_from_slice(key);
    kde
}

/// Build a GTK KDE: OUI(3) type(1) keyinfo(1) reserved(1) GTK(16).
fn build_gtk_kde(gtk: &[u8; 16], key_info: u8) -> Vec<u8> {
    let mut kde = vec![
        0xDD,
        (6 + gtk.len()) as u8,
        0x00,
        0x0F,
        0xAC,
        0x01,
        key_info,
        0x00,
    ];
    kde.extend_from_slice(gtk);
    kde
}

fn oci(operating_class: u8, channel: u8) -> Ieee80211Oci {
    Ieee80211Oci {
        operating_class,
        channel,
        segment: 0,
    }
}

#[test]
fn oci_from_freq_maps_channels_and_op_classes() {
    assert_eq!(Ieee80211Oci::from_freq(2412), Some(oci(81, 1)));
    assert_eq!(Ieee80211Oci::from_freq(2462), Some(oci(81, 11)));
    assert_eq!(Ieee80211Oci::from_freq(5180), Some(oci(115, 36)));
    assert_eq!(Ieee80211Oci::from_freq(5220), Some(oci(115, 44)));
    assert_eq!(Ieee80211Oci::from_freq(5745), Some(oci(118, 149)));
    assert_eq!(Ieee80211Oci::from_freq(2410), None);
    assert_eq!(Ieee80211Oci::from_freq(5000), None);
}

#[test]
fn oci_matches_primary_frequency() {
    assert!(oci(81, 1).matches_freq(2412));
    assert!(!oci(81, 6).matches_freq(2412));
    assert!(oci(115, 36).matches_freq(5180));
    assert!(!oci(81, 1).matches_freq(5180));
}

#[test]
fn oci_kde_roundtrip() {
    let oci = oci(81, 1);
    let kde = build_oci_kde(oci);
    assert_eq!(&kde[..6], &[0xDD, 7, 0x00, 0x0F, 0xAC, 13]);
    assert_eq!(kde[6..], oci.to_bytes());
    assert_eq!(parse_oci_kde(&kde), Some(oci));
}

/// The OCI payload is parsed as a three-octet zerocopy struct: the
/// octets that follow it are not part of the OCI, and a payload too
/// short for the struct is refused instead of read out of bounds.
#[test]
fn oci_buffer_split() {
    let buffer = Ieee80211OciBuffer::new(115, 44, 0);
    assert_eq!(Ieee80211OciBuffer::LEN, 3);

    let (parsed, rest) =
        Ieee80211OciBuffer::split(&[115, 44, 0, 0xAA]).unwrap();
    assert_eq!(*parsed, buffer);
    assert_eq!(rest, &[0xAA]);

    assert_eq!(Ieee80211Oci::from(buffer), oci(115, 44));
    // `to_bytes()` and the buffer describe the same three octets.
    let octets = oci(115, 44).to_bytes();
    let (roundtrip, _) = Ieee80211OciBuffer::split(&octets).unwrap();
    assert_eq!(*roundtrip, buffer);

    assert!(Ieee80211OciBuffer::split(&[]).is_err());
    assert!(Ieee80211OciBuffer::split(&[115, 44]).is_err());
}

/// The OCI KDE is a nine-octet zerocopy struct: `build_oci_kde()` emits
/// it, and parsing one checks the Element ID, Length, OUI and KDE type
/// before handing out the OCI.
#[test]
fn oci_key_data_elem_buffer_split() {
    let oci = oci(115, 44);
    let kde = build_oci_kde(oci);
    assert_eq!(Ieee80211OciKeyDataElemBuffer::LEN, 9);
    assert_eq!(Ieee80211OciKeyDataElemBuffer::LEN, kde.len());

    let (parsed, rest) = Ieee80211OciKeyDataElemBuffer::split(&kde).unwrap();
    assert_eq!(parsed, &Ieee80211OciKeyDataElemBuffer::new(oci));
    assert_eq!(parsed.oci(), oci);
    assert!(rest.is_empty());

    // A key data element of another type, a truncated OCI key data
    // element and an element of another Element ID are all refused.
    let gtk = build_gtk_kde(&[0x77u8; 16], 0x01);
    assert!(Ieee80211OciKeyDataElemBuffer::split(&gtk).is_err());
    assert!(Ieee80211OciKeyDataElemBuffer::split(&kde[..8]).is_err());
    let rsne_like = [ELEMENT_ID_RSN, 7, 0, 0, 0, 0, 0, 0, 0];
    assert!(Ieee80211OciKeyDataElemBuffer::split(&rsne_like).is_err());
}

#[test]
fn oci_kde_skips_other_kdes_and_truncated_data() {
    let gtk = [0x77u8; 16];
    let mut key_data = build_gtk_kde(&gtk, 0x01);
    key_data.extend_from_slice(&build_oci_kde(oci(115, 44)));
    assert_eq!(parse_oci_kde(&key_data), Some(oci(115, 44)));

    // A truncated trailing element ends the scan.
    key_data.extend_from_slice(&[0xDD, 7, 0x00]);
    assert_eq!(parse_oci_kde(&key_data), Some(oci(115, 44)));
    assert_eq!(parse_oci_kde(&[0xDD, 7, 0x00]), None);
}

#[test]
fn parse_gtk_kde_extracts_key_index_and_key() {
    let gtk = [0x77u8; 16];
    let kde = build_gtk_kde(&gtk, 0x01);
    let (idx, parsed) = parse_gtk_kde(&kde).unwrap();
    assert_eq!(idx, 1);
    assert_eq!(parsed, gtk.to_vec());

    // Key index is the low two bits of the key-info octet.
    let kde = build_gtk_kde(&gtk, 0x06);
    assert_eq!(parse_gtk_kde(&kde), Some((2, gtk.to_vec())));
}

#[test]
fn parse_key_data_kdes_all() {
    let gtk = [0x77u8; 16];
    let igtk = [0x88u8; 16];
    let bigtk = [0x99u8; 16];
    let ipn = [1, 2, 3, 4, 5, 6];
    let rsne = vec![0x30, 0x02, 0x01, 0x00];
    let rsnxe = vec![0xF4, 0x01, 0x20];

    let mut key_data = build_gtk_kde(&gtk, 0x02);
    key_data.extend_from_slice(&build_mgmt_key_kde(9, 4, &ipn, &igtk));
    key_data.extend_from_slice(&build_mgmt_key_kde(14, 6, &ipn, &bigtk));
    // Key ID KDE (Extended Key ID): OUI(3) type(10) key_id(2 LE).
    key_data.extend_from_slice(&[0xDD, 6, 0x00, 0x0F, 0xAC, 10, 1, 0]);
    // Transition Disable KDE (WFA OUI 50:6F:9A, type 0x20, bitmap 0x09
    // = WPA3-Personal + WPA3-Enterprise disabled).
    key_data.extend_from_slice(&[0xDD, 5, 0x50, 0x6F, 0x9A, 0x20, 0x09]);
    key_data.extend_from_slice(&rsne);
    key_data.extend_from_slice(&rsnxe);

    let kdes = parse_key_data_kdes(&key_data);
    assert_eq!(kdes.gtk, Some((2, gtk.to_vec())));
    assert_eq!(
        kdes.igtk
            .as_ref()
            .map(|k| (k.key_index, k.ipn, k.key.clone())),
        Some((4, ipn, igtk.to_vec()))
    );
    assert_eq!(
        kdes.bigtk
            .as_ref()
            .map(|k| (k.key_index, k.ipn, k.key.clone())),
        Some((6, ipn, bigtk.to_vec()))
    );
    assert_eq!(kdes.rsne.as_deref(), Some(rsne.as_slice()));
    assert_eq!(kdes.rsnxe.as_deref(), Some(rsnxe.as_slice()));
    assert_eq!(kdes.transition_disable, Some(0x09));
    assert_eq!(kdes.key_id, Some(1));
    // parse_gtk_kde keeps its GTK-only contract on top of the full parser.
    assert_eq!(parse_gtk_kde(&key_data), Some((2, gtk.to_vec())));
}

#[test]
fn parse_key_data_kdes_ignores_malformed_and_unknown() {
    assert_eq!(
        parse_key_data_kdes(&[0xDD, 3, 0x00, 0x0F, 0xAC]),
        Default::default()
    );
    // Unknown vendor KDE (type 0x7F) and unknown plain IE are skipped,
    // while a following GTK KDE is still parsed.
    let gtk = [0x55u8; 16];
    let mut key_data = vec![0xDD, 5, 0x00, 0x0F, 0xAC, 0x7F, 0x00];
    key_data.extend_from_slice(&[0x2A, 0x01, 0x00]);
    key_data.extend_from_slice(&build_gtk_kde(&gtk, 0x00));
    let kdes = parse_key_data_kdes(&key_data);
    assert_eq!(kdes.gtk, Some((0, gtk.to_vec())));
    assert_eq!(kdes.key_id, None);
}
