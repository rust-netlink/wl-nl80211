// SPDX-License-Identifier: MIT

use futures::{FutureExt, Stream, StreamExt, TryStream, future::Either};
use genetlink::GenetlinkHandle;
use netlink_packet_core::NetlinkMessage;
use netlink_packet_generic::GenlMessage;

use crate::{
    Nl80211ConnectionHandle, Nl80211Error, Nl80211InterfaceHandle,
    Nl80211Message, Nl80211ScanHandle, Nl80211StartApRequest,
    Nl80211StationAddRequest, Nl80211StationDelRequest, Nl80211StationHandle,
    Nl80211StationSetRequest, Nl80211StopApRequest, Nl80211SurveyHandle,
    Nl80211WiphyHandle, try_nl80211,
};

#[derive(Clone, Debug)]
pub struct Nl80211Handle {
    pub handle: GenetlinkHandle,
}

impl Nl80211Handle {
    pub(crate) fn new(handle: GenetlinkHandle) -> Self {
        Nl80211Handle { handle }
    }

    // equivalent to `iw dev` command
    pub fn interface(&self) -> Nl80211InterfaceHandle {
        Nl80211InterfaceHandle::new(self.clone())
    }

    // equivalent to `iw dev DEVICE station` command
    pub fn station(&self) -> Nl80211StationHandle {
        Nl80211StationHandle::new(self.clone())
    }

    // equivalent to `iw phy` command
    pub fn wireless_physic(&self) -> Nl80211WiphyHandle {
        Nl80211WiphyHandle::new(self.clone())
    }

    // equivalent to `iw dev DEVICE scan` command
    pub fn scan(&self) -> Nl80211ScanHandle {
        Nl80211ScanHandle::new(self.clone())
    }

    // equivalent to `iw dev DEVICE connect` / `disconnect` commands
    pub fn connection(&self) -> Nl80211ConnectionHandle {
        Nl80211ConnectionHandle::new(self.clone())
    }

    // equivalent to `iw DEVICE survey dump` command
    pub fn survey(&self) -> Nl80211SurveyHandle {
        Nl80211SurveyHandle::new(self.clone())
    }

    /// Start an access point (`NL80211_CMD_START_AP`). The attributes are
    /// normally produced by [`crate::Nl80211StartAp`].
    pub fn start_ap(
        &mut self,
        attributes: Vec<crate::Nl80211Attr>,
    ) -> Nl80211StartApRequest {
        Nl80211StartApRequest::new(self.clone(), attributes)
    }

    /// Stop an access point (`NL80211_CMD_STOP_AP`). The attributes are
    /// normally produced by [`crate::Nl80211StopAp`].
    pub fn stop_ap(
        &mut self,
        attributes: Vec<crate::Nl80211Attr>,
    ) -> Nl80211StopApRequest {
        Nl80211StopApRequest::new(self.clone(), attributes)
    }

    /// Add a station to an AP interface (`NL80211_CMD_NEW_STATION`).
    pub fn station_add(
        &mut self,
        attributes: Vec<crate::Nl80211Attr>,
    ) -> Nl80211StationAddRequest {
        Nl80211StationAddRequest::new(self.clone(), attributes)
    }

    /// Modify a station (`NL80211_CMD_SET_STATION`).
    pub fn station_set(
        &mut self,
        attributes: Vec<crate::Nl80211Attr>,
    ) -> Nl80211StationSetRequest {
        Nl80211StationSetRequest::new(self.clone(), attributes)
    }

    /// Delete a station (`NL80211_CMD_DEL_STATION`).
    pub fn station_del(
        &mut self,
        attributes: Vec<crate::Nl80211Attr>,
    ) -> Nl80211StationDelRequest {
        Nl80211StationDelRequest::new(self.clone(), attributes)
    }

    pub async fn request(
        &mut self,
        message: NetlinkMessage<GenlMessage<Nl80211Message>>,
    ) -> Result<
        impl Stream<
            Item = Result<
                NetlinkMessage<GenlMessage<Nl80211Message>>,
                Nl80211Error,
            >,
        > + use<>,
        Nl80211Error,
    > {
        self.handle
            .request(message)
            .await
            .map(|stream| stream.map(|item| item.map_err(Nl80211Error::from)))
            .map_err(|e| {
                Nl80211Error::RequestFailed(format!(
                    "BUG: Request failed with {e}"
                ))
            })
    }
}

pub(crate) async fn nl80211_execute(
    handle: &mut Nl80211Handle,
    nl80211_msg: Nl80211Message,
    header_flags: u16,
) -> impl TryStream<Ok = GenlMessage<Nl80211Message>, Error = Nl80211Error> + use<>
{
    let mut nl_msg =
        NetlinkMessage::from(GenlMessage::from_payload(nl80211_msg));

    nl_msg.header.flags = header_flags;

    match handle.request(nl_msg).await {
        Ok(response) => {
            Either::Left(response.map(move |msg| Ok(try_nl80211!(msg))))
        }
        Err(e) => Either::Right(
            futures::future::err::<GenlMessage<Nl80211Message>, Nl80211Error>(
                e,
            )
            .into_stream(),
        ),
    }
}
