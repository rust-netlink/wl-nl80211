// SPDX-License-Identifier: MIT

// Listen to nl80211 multicast events, equivalent to `iw event`.
//
// Run as root (multicast group membership needs CAP_NET_ADMIN):
//
//     cargo run --example nl80211_multicast -- 5

use futures::StreamExt;
use tokio::time::Duration;
use wl_nl80211::{
    new_multicast_connection, Nl80211Event, Nl80211MulticastGroup,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let duration = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(3)
        .min(60);

    let (connection, _handle, mut messages) = new_multicast_connection(&[
        Nl80211MulticastGroup::Config,
        Nl80211MulticastGroup::Scan,
        Nl80211MulticastGroup::Mlme,
    ])?;
    tokio::spawn(connection);

    let _ = tokio::time::timeout(Duration::from_secs(duration), async {
        while let Some((msg, _)) = messages.next().await {
            if let Some(event) = Nl80211Event::parse(msg) {
                println!("{event:?}");
            }
        }
    })
    .await;
    Ok(())
}
