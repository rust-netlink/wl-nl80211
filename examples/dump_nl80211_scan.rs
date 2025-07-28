// SPDX-License-Identifier: MIT

use std::env::args;

use anyhow::{bail, Context, Error};
use futures::stream::TryStreamExt;
use netlink_packet_utils::{Emitable, Parseable};
use wl_nl80211::Nl80211Element;

fn main() -> Result<(), Error> {
    let argv: Vec<_> = args().collect();

    if argv.len() < 2 {
        eprintln!("Usage: dump_nl80211_scan <interface index>");
        bail!("Required arguments not given");
    }

    let err_msg = format!("Invalid interface index value: {}", argv[1]);
    let index = argv[1].parse::<u32>().context(err_msg)?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .unwrap();
    rt.block_on(dump_scan(index));

    Ok(())
}

async fn dump_scan(if_index: u32) {
    let (connection, handle, _) = wl_nl80211::new_connection().unwrap();
    tokio::spawn(connection);

    let mut scan_handle = handle.scan().dump(if_index).execute().await;

    let mut msgs = Vec::new();
    while let Some(msg) = scan_handle.try_next().await.unwrap() {
        msgs.push(msg);
    }
    assert!(!msgs.is_empty());
    for msg in msgs {
        println!("{msg:?}");

        println!("Information Elements");
        let ie: Vec<_> =
            msg.payload.attributes.iter().filter_map(|attr| match attr {
                wl_nl80211::Nl80211Attr::Bss(info) => {
                    let ies: Vec<_>  = info.iter().filter_map(|info| match info {
                    wl_nl80211::Nl80211BssInfo::BeaconInformationElements(ie)| wl_nl80211::Nl80211BssInfo::InformationElements(ie) | wl_nl80211::Nl80211BssInfo::ProbeResponseInformationElements(ie) =>
                        Some(wl_nl80211::Nl80211Elements::parse(ie).unwrap()),
                        _ => None,
                    }).collect();
                    Some(ies)
                },
                _ => None,
            }).flatten().collect();

        println!("{ie:?}");
    }
}
