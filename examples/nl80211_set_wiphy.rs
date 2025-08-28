// SPDX-License-Identifier: MIT

use std::env::args;

use futures::stream::TryStreamExt;
use netlink_packet_core::{DecodeError, ErrorContext};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let argv: Vec<_> = args().collect();

    if argv.len() < 2 {
        eprintln!("Usage: nl80211_set_wiphy <interface index>");
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
    rt.block_on(set_wiphy_params(index));

    Ok(())
}

async fn set_wiphy_params(if_index: u32) {
    let (connection, handle, _) = wl_nl80211::new_connection().unwrap();
    tokio::spawn(connection);

    let attrs = wl_nl80211::Nl80211Channel::new(if_index)
        .frequency(5180)
        .frequency_offset(0)
        .channel_width(wl_nl80211::Nl80211ChannelWidth::NoHt20)
        .channel_type(wl_nl80211::Nl80211HtWiphyChannelType::NoHt)
        .center_frequency(5180)
        .build();

    let mut channel_handle =
        handle.wireless_physic().set(attrs).execute().await;
    channel_handle.try_next().await.unwrap();
}
