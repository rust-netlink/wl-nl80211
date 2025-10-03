// SPDX-License-Identifier: MIT

//! CLI tool to create and delete interfaces.
//!
//! To create an interface:
//!
//! ```
//! .../interfaces new [wiphy] [ifname] [type]
//! ```
//!
//! To delete:
//!
//! ```
//! .../interfaces del [ifname]
//! ```

use anyhow::{anyhow, bail};
use futures::stream::TryStreamExt;
use log::{debug, info};
use std::env;
use wl_nl80211::{
    Nl80211Attr, Nl80211Command, Nl80211Handle, Nl80211Interface,
    Nl80211InterfaceType, Nl80211Message, Nl80211NewInterface,
};

fn main() -> anyhow::Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let _guard = rt.enter();

    let (connection, handle, _) = wl_nl80211::new_connection()?;
    tokio::spawn(connection);

    let mut args = env::args().skip(1);
    // Simplistic CLI parsing should be replaced with clap, etc, in a real tool
    match args.next().as_deref() {
        Some("new") => {
            let phy_name = args
                .next()
                .ok_or_else(|| anyhow!("No wiphy name specified"))?;
            let if_name = args
                .next()
                .ok_or_else(|| anyhow!("No interface specified"))?;
            let if_type = args
                .next()
                .map(|ift| match ift.as_str() {
                    "monitor" => Ok(Nl80211InterfaceType::Monitor),
                    _ => Err(anyhow!("Unknown interface type")),
                })
                .ok_or_else(|| anyhow!("No type specified"))
                .flatten()?;
            rt.block_on(new_interface(handle, phy_name, if_name, if_type))
        }
        Some("del") => {
            let if_name = args
                .next()
                .ok_or_else(|| anyhow!("No interface specified"))?;

            rt.block_on(del_interface(handle, if_name))
        }
        None | Some(_) => bail!("Must specify op: <new> or <del>"),
    }
}

async fn new_interface(
    handle: Nl80211Handle,
    wiphy_name: String,
    if_name: String,
    if_type: Nl80211InterfaceType,
) -> anyhow::Result<()> {
    let mut wiphy_attributes = std::pin::pin!(handle
        .wireless_physic()
        .get()
        .execute()
        .await
	        .try_filter_map(|msg| {
            let wn = wiphy_name.clone();
            async move {
	            match msg.payload {
	                Nl80211Message {
	                    cmd: Nl80211Command::NewWiphy,
	                    attributes,
	                } if attributes
	                    .iter()
	                    .any(|f| matches!(f, wl_nl80211::Nl80211Attr::WiphyName(name) if *name == *wn))
	                 => Ok(Some(attributes)),
	                _ => Ok(None),
	            }
	        }
        }));

    let wiphy_id = *wiphy_attributes
        .try_next()
        .await?
        .ok_or_else(|| anyhow!("Could not find wiphy <{wiphy_name}>"))?
        .iter()
        .find_map(|attr| match attr {
            Nl80211Attr::Wiphy(i) => Some(i),
            _ => None,
        })
        .ok_or_else(|| anyhow!("Could not find wiphy <{wiphy_name}>"))?;

    debug!("Using wiphy id {wiphy_id}");
    let mut if_handle = handle
        .interface()
        .add(Nl80211NewInterface::new(wiphy_id, if_type, if_name).build())
        .execute()
        .await;

    while let Some(msg) = if_handle.try_next().await? {
        info!("Response: {msg:?}")
    }

    Ok(())
}

async fn del_interface(
    handle: Nl80211Handle,
    if_name: String,
) -> anyhow::Result<()> {
    let mut if_attributes = std::pin::pin!(handle
	        .interface()
            // no attributes = all interfaces
	        .get(vec![])
	        .execute()
	        .await
	        .try_filter_map(|msg| {
                let iname = if_name.clone();
                async move {
                    match msg.payload {
                        Nl80211Message {
                            cmd: Nl80211Command::NewInterface,
                            attributes,
                        } if attributes
                            .iter()
                            .any(|f| matches!(f, wl_nl80211::Nl80211Attr::IfName(name) if *name == iname))
                         => Ok(Some(attributes)),
                        _ => Ok(None),
                    }
	            }
        }));

    let if_index = *if_attributes
        .try_next()
        .await?
        .ok_or_else(|| anyhow!("Could not find interface <{if_name}>"))?
        .iter()
        .find_map(|attr| match attr {
            Nl80211Attr::IfIndex(i) => Some(i),
            _ => None,
        })
        .ok_or_else(|| anyhow!("Could not find interface <{if_name}>"))?;

    debug!("Using interface index {if_index}");

    let mut if_handle = handle
        .interface()
        .delete(Nl80211Interface::new(if_index).build())
        .execute()
        .await;

    while let Some(msg) = if_handle.try_next().await? {
        info!("Response: {msg:?}")
    }

    Ok(())
}
