// SPDX-License-Identifier: MIT

use std::env::args;

use futures::{stream::TryStreamExt, StreamExt};
use netlink_packet_core::{DecodeError, ErrorContext, ParseableParametrized};
use netlink_packet_core::{NetlinkMessage, NetlinkPayload, NLM_F_REQUEST};
use netlink_packet_generic::{
    ctrl::{
        nlas::{GenlCtrlAttrs, McastGrpAttrs},
        GenlCtrl, GenlCtrlCmd,
    },
    GenlMessage,
};
use netlink_sys::AsyncSocket;
use wl_nl80211::{Nl80211Command, Nl80211Message};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let argv: Vec<_> = args().collect();

    if argv.len() < 2 {
        return Err(Box::new(std::io::Error::other(
            "Usage: nl80211_trigger_scan <interface index>",
        )));
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
    let (mut connection, handle, mut messages) = wl_nl80211::new_connection()?;

    // Attach the connection socket to the multicast scan group to find out,
    // when the scan is finished.
    let socket = connection.socket_mut().socket_mut();
    socket.bind_auto()?;
    socket.add_membership(get_scan_multicast_id().await?)?;

    tokio::spawn(connection);

    let attrs = wl_nl80211::Nl80211Scan::new(if_index)
        .duration(5000)
        .passive(true)
        .build();

    let mut scan_handle = handle.scan().trigger(attrs).execute().await;

    let mut msgs = Vec::new();
    while let Some(msg) = scan_handle.try_next().await? {
        msgs.push(msg);
    }

    while let Some((message, _)) = messages.next().await {
        match message.payload {
            NetlinkPayload::InnerMessage(msg) => {
                let msg = Nl80211Message::parse_with_param(
                    msg.payload.as_slice(),
                    msg.header,
                )?;
                if msg.cmd == Nl80211Command::NewScanResults {
                    break;
                }
            }
            _ => continue,
        }
    }

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

async fn get_scan_multicast_id() -> Result<u32, Box<dyn std::error::Error>> {
    let (conn, mut handle, _) = wl_nl80211::new_connection()?;
    tokio::spawn(conn);

    let mut nl_msg =
        NetlinkMessage::from(GenlMessage::from_payload(GenlCtrl {
            cmd: GenlCtrlCmd::GetFamily,
            nlas: vec![GenlCtrlAttrs::FamilyName("nl80211".to_owned())],
        }));

    // To get the mcast groups for the nl80211 family, we must also set the
    // message type id
    nl_msg.header.message_type =
        handle.handle.resolve_family_id::<Nl80211Message>().await?;
    // This is a request, but not a dump. Which means, the family name has to be
    // specified, to obtain it's information.
    nl_msg.header.flags = NLM_F_REQUEST;

    let responses = handle.handle.request(nl_msg).await?;
    let nl80211_family: Vec<Vec<GenlCtrlAttrs>> = responses
        .try_filter_map(|msg| async move {
            match msg.payload {
                NetlinkPayload::InnerMessage(genlmsg)
                    if genlmsg.payload.cmd == GenlCtrlCmd::NewFamily
                        && genlmsg.payload.nlas.contains(
                            &GenlCtrlAttrs::FamilyName("nl80211".to_owned()),
                        ) =>
                {
                    Ok(Some(genlmsg.payload.nlas.clone()))
                }
                _ => Ok(None),
            }
        })
        .try_collect()
        .await?;

    // Now get the mcid for "nl80211" "scan" group
    let scan_multicast_id = nl80211_family
        .first()
        .ok_or_else(|| anyhow!("Missing \"nl80211\" family"))?
        .iter()
        .find_map(|attr| match attr {
            GenlCtrlAttrs::McastGroups(mcast_groups) => Some(mcast_groups),
            _ => None,
        })
        .ok_or_else(|| anyhow!("Missing McastGroup attribute"))?
        .iter()
        .find(|grp| grp.contains(&McastGrpAttrs::Name("scan".to_owned())))
        .ok_or_else(|| anyhow!("Missing scan group"))?
        .iter()
        .find_map(|grp_attr| match grp_attr {
            McastGrpAttrs::Id(id) => Some(*id),
            _ => None,
        })
        .ok_or_else(|| anyhow!("No multicast id defined for scan group"))?;

    Ok(scan_multicast_id)
}
