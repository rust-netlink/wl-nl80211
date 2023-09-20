// SPDX-License-Identifier: MIT

use crate::{Nl80211Handle, Nl80211StationGetRequest};

pub struct Nl80211StationHandle(Nl80211Handle);

impl Nl80211StationHandle {
    pub fn new(handle: Nl80211Handle) -> Self {
        Nl80211StationHandle(handle)
    }

    /// Retrieve the stations
    /// (equivalent to `iw dev DEV station dump`)
    pub fn dump(&mut self, if_index: u32) -> Nl80211StationGetRequest {
        Nl80211StationGetRequest::new(self.0.clone(), if_index, None)
    }
}
