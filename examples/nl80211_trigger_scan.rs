// SPDX-License-Identifier: MIT

use std::env::args;

use futures::stream::TryStreamExt;
use netlink_packet_core::{DecodeError, ErrorContext};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let argv: Vec<_> = args().collect();

    if argv.len() < 2 {
        eprintln!("Usage: nl80211_trigger_scan <interface index>");
        panic!("Required arguments not given");
    }

    let err_msg = format!("Invalid interface index value: {}", argv[1]);
    let index = argv[1]
        .parse::<u32>()
        .map_err(|e| DecodeError::from(e.to_string()))
        .context(err_msg)?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .unwrap();
    rt.block_on(dump_scan(index))?;

    Ok(())
}

async fn dump_scan(if_index: u32) -> Result<(), Box<dyn std::error::Error>> {
    let (connection, handle, _) = wl_nl80211::new_connection()?;
    tokio::spawn(connection);

    let duration = 5000;
    let attrs = wl_nl80211::Nl80211Scan::new(if_index)
        .duration(duration)
        .passive(true)
        .build();

    let mut scan_handle = handle.scan().trigger(attrs).execute().await;

    let mut msgs = Vec::new();
    while let Some(msg) = scan_handle.try_next().await? {
        msgs.push(msg);
    }
    tokio::time::sleep(std::time::Duration::from_millis(duration.into())).await;

    let mut dump = handle.scan().dump(if_index).execute().await;
    let mut msgs = Vec::new();
    while let Some(msg) = dump.try_next().await? {
        msgs.push(msg);
    }
    assert!(!msgs.is_empty());
    for msg in msgs {
        println!("{msg:?}");
    }
    Ok(())
}
