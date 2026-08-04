// SPDX-License-Identifier: MIT

use std::collections::HashMap;
use std::io;

use futures::channel::mpsc::UnboundedReceiver;
use genetlink::message::RawGenlMessage;
use netlink_packet_core::{
    Emitable, NetlinkMessage, NetlinkPayload, NLM_F_REQUEST,
};
use netlink_packet_generic::{
    ctrl::{
        nlas::{GenlCtrlAttrs, McastGrpAttrs},
        GenlCtrl, GenlCtrlCmd,
    },
    GenlMessage,
};
use netlink_proto::Connection;
use netlink_sys::{
    protocols::NETLINK_GENERIC, AsyncSocket, Socket, SocketAddr,
};

use crate::Nl80211Handle;

const NL80211_FAMILY_NAME: &str = "nl80211";
const GENL_ID_CTRL: u16 = 0x10;

/// Multicast groups of the nl80211 family.
///
/// Mirrors the kernel `NL80211_MULTICAST_GROUP_*` names; the numeric group
/// IDs are dynamic per system and resolved at
/// [`new_multicast_connection`] time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Nl80211MulticastGroup {
    /// `config` group: interface/connection configuration events.
    Config,
    /// `scan` group: scan start / new scan results events.
    Scan,
    /// `regulatory` group: regulatory domain change events.
    Regulatory,
    /// `mlme` group: management frame and association events.
    Mlme,
    /// `vendor` group: vendor-specific events.
    Vendor,
    /// `nan` group: NAN (Neighbor Awareness Networking) events.
    Nan,
    /// `testmode` group: testmode events.
    Testmode,
}

impl Nl80211MulticastGroup {
    /// The kernel group name, as used by the `GENL_CMD_GETFAMILY` reply.
    pub fn name(self) -> &'static str {
        match self {
            Nl80211MulticastGroup::Config => "config",
            Nl80211MulticastGroup::Scan => "scan",
            Nl80211MulticastGroup::Regulatory => "regulatory",
            Nl80211MulticastGroup::Mlme => "mlme",
            Nl80211MulticastGroup::Vendor => "vendor",
            Nl80211MulticastGroup::Nan => "nan",
            Nl80211MulticastGroup::Testmode => "testmode",
        }
    }
}

#[cfg(feature = "tokio_socket")]
#[allow(clippy::type_complexity)]
pub fn new_connection() -> io::Result<(
    Connection<RawGenlMessage>,
    Nl80211Handle,
    UnboundedReceiver<(NetlinkMessage<RawGenlMessage>, SocketAddr)>,
)> {
    new_connection_with_socket()
}

/// Create a new nl80211 connection joined to the given multicast groups,
/// equivalent to `iw event`.
///
/// Use a dedicated connection for events instead of reusing the one issuing
/// requests: an event (e.g. `NEW_SCAN_RESULTS`) can be emitted by the kernel
/// before the requesting socket starts listening on the group (see the iw
/// source for details).
#[cfg(feature = "tokio_socket")]
#[allow(clippy::type_complexity)]
pub fn new_multicast_connection(
    groups: &[Nl80211MulticastGroup],
) -> io::Result<(
    Connection<RawGenlMessage>,
    Nl80211Handle,
    UnboundedReceiver<(NetlinkMessage<RawGenlMessage>, SocketAddr)>,
)> {
    new_multicast_connection_with_socket(groups)
}

#[allow(clippy::type_complexity)]
pub fn new_connection_with_socket<S>() -> io::Result<(
    Connection<RawGenlMessage, S>,
    Nl80211Handle,
    UnboundedReceiver<(NetlinkMessage<RawGenlMessage>, SocketAddr)>,
)>
where
    S: AsyncSocket,
{
    let (conn, handle, messages) = genetlink::new_connection_with_socket()?;
    Ok((conn, Nl80211Handle::new(handle), messages))
}

/// Variant of [`new_multicast_connection`] that allows specifying a socket
/// type to use for async handling.
#[allow(clippy::type_complexity)]
pub fn new_multicast_connection_with_socket<S>(
    groups: &[Nl80211MulticastGroup],
) -> io::Result<(
    Connection<RawGenlMessage, S>,
    Nl80211Handle,
    UnboundedReceiver<(NetlinkMessage<RawGenlMessage>, SocketAddr)>,
)>
where
    S: AsyncSocket,
{
    let (mut conn, handle, messages): (Connection<RawGenlMessage, S>, _, _) =
        genetlink::new_connection_with_socket()?;
    let group_ids = query_multicast_group_ids()?;

    // Bind the socket so it gets a nonzero portid: netlink_proto leaves the
    // socket unbound until the first request is sent, and the kernel skips
    // unbound sockets (portid 0, same as the multicast sender) when
    // delivering broadcasts.
    conn.socket_mut()
        .socket_mut()
        .bind(&SocketAddr::new(0, 0))?;

    // The nl80211 multicast group ids are dynamic and can exceed the 32
    // groups expressible in the legacy `nl_groups` bind bitmask, so join
    // each group with `NETLINK_ADD_MEMBERSHIP` (the same mechanism `iw
    // event` uses).
    for group in groups {
        match group_ids.get(group.name()) {
            Some(id) => {
                conn.socket_mut().socket_mut().add_membership(*id)?;
            }
            None => {
                log::warn!("nl80211 multicast group {:?} not found", group);
            }
        }
    }

    Ok((conn, Nl80211Handle::new(handle), messages))
}

/// Query the nl80211 family and return a map of group name -> group ID.
///
/// The nl80211 multicast group IDs are dynamic per system, so they are
/// resolved via a blocking `GENL_CMD_GETFAMILY` query on the generic netlink
/// control socket before joining the groups.
fn query_multicast_group_ids() -> io::Result<HashMap<String, u32>> {
    let mut sock = Socket::new(NETLINK_GENERIC)?;
    sock.bind(&SocketAddr::new(0, 0))?;
    sock.connect(&SocketAddr::new(0, 0))?;

    let genl_ctrl = GenlCtrl {
        cmd: GenlCtrlCmd::GetFamily,
        nlas: vec![GenlCtrlAttrs::FamilyName(NL80211_FAMILY_NAME.to_string())],
    };
    let mut genl_msg: GenlMessage<GenlCtrl> =
        GenlMessage::from_payload(genl_ctrl);
    genl_msg.finalize();
    // The control family has a static family id (0x10).
    genl_msg.set_resolved_family_id(GENL_ID_CTRL);
    let mut nl_msg = NetlinkMessage::from(genl_msg);
    nl_msg.header.flags = NLM_F_REQUEST;
    nl_msg.finalize();

    let mut buf = vec![0u8; nl_msg.buffer_len()];
    nl_msg.emit(&mut buf);
    sock.send(&buf, 0)?;

    let (recv_buf, _) = sock.recv_from_full()?;

    let rx_packet =
        NetlinkMessage::<GenlMessage<GenlCtrl>>::deserialize(&recv_buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let mut groups = HashMap::new();
    if let NetlinkPayload::InnerMessage(genlmsg) = rx_packet.payload {
        for nla in &genlmsg.payload.nlas {
            if let GenlCtrlAttrs::McastGroups(mcast_groups) = nla {
                for grp_attrs in mcast_groups {
                    let mut name = String::new();
                    let mut id = 0;
                    for attr in grp_attrs {
                        match attr {
                            McastGrpAttrs::Name(n) => name = n.clone(),
                            McastGrpAttrs::Id(gid) => id = *gid,
                        }
                    }
                    if !name.is_empty() {
                        groups.insert(name, id);
                    }
                }
            }
        }
    }

    if groups.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no multicast groups found for nl80211 family",
        ));
    }

    Ok(groups)
}
