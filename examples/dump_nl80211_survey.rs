// SPDX-License-Identifier: MIT

use std::env::args;

use futures::stream::TryStreamExt;
use netlink_packet_core::{DecodeError, ErrorContext};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let argv: Vec<_> = args().collect();

    if argv.len() < 2 {
        eprintln!("Usage: dump_nl80211_survey <interface index>");
        panic!("Required arguments not given");
    }

    let err_msg = format!("Invalid interface index value: {}", argv[1]);
    let index = argv[1]
        .parse::<u32>()
        .map_err(|e| DecodeError::from(e.to_string()))
        .context(err_msg)?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .unwrap();
    rt.block_on(dump_survey(index))?;

    Ok(())
}

async fn dump_survey(if_index: u32) -> Result<(), Box<dyn std::error::Error>> {
    let (connection, handle, _) = wl_nl80211::new_connection()?;
    tokio::spawn(connection);

    let mut survey_handle = handle
        .survey()
        .dump(wl_nl80211::Nl80211Survey::new(if_index).radio(true).build())
        .execute()
        .await;

    let mut msgs = Vec::new();
    while let Some(msg) = survey_handle.try_next().await? {
        msgs.push(msg);
    }
    assert!(!msgs.is_empty());
    for msg in msgs {
        println!("{:?}", msg);
    }
    Ok(())
}
