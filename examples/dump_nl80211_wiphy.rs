// SPDX-License-Identifier: MIT

use futures::stream::TryStreamExt;

fn main() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .unwrap();
    rt.block_on(get_wireless_physics());
}

async fn get_wireless_physics() {
    let (connection, handle, _) = wl_nl80211::new_connection().unwrap();
    tokio::spawn(connection);

    let mut phy_handle = handle.wireless_physic().get().execute().await;

    let mut msgs = Vec::new();
    while let Some(msg) = phy_handle.try_next().await.unwrap() {
        msgs.push(msg);
    }
    assert!(!msgs.is_empty());
    for msg in msgs {
        println!("{msg:?}");
    }
}
