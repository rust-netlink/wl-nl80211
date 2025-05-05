// SPDX-License-Identifier: MIT

use std::env::args;

use anyhow::{bail, Context, Error};
use futures::stream::TryStreamExt;

fn main() -> Result<(), Error> {
    let argv: Vec<_> = args().collect();

    if argv.len() < 2 {
        eprintln!("Usage: nl80211_trigger_scan <interface index>");
        bail!("Required arguments not given");
    }

    let err_msg = format!("Invalid interface index value: {}", argv[1]);
    let index = argv[1].parse::<u32>().context(err_msg)?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .unwrap();
    rt.block_on(dump_scan(index));

    Ok(())
}

async fn dump_scan(if_index: u32) {
    let (connection, handle, _) = wl_nl80211::new_connection().unwrap();
    tokio::spawn(connection);

    let attrs = wl_nl80211::Nl80211Scan::new(if_index)
        .duration(5000)
        .passive(true)
        .build();

    let mut scan_handle = handle.scan().trigger(attrs).execute().await;

    let mut msgs = Vec::new();
    while let Some(msg) = scan_handle.try_next().await.unwrap() {
        msgs.push(msg);
    }
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    let mut dump = handle.scan().dump(if_index).execute().await;
    let mut msgs = Vec::new();
    while let Some(msg) = dump.try_next().await.unwrap() {
        msgs.push(msg);
    }
    assert!(!msgs.is_empty());
    for msg in msgs {
        println!("{msg:?}");
    }
}
