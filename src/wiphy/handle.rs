// SPDX-License-Identifier: MIT

use crate::{Nl80211Handle, Nl80211WiphyGetRequest};

#[derive(Debug)]
pub struct Nl80211WiphyHandle(Nl80211Handle);

impl Nl80211WiphyHandle {
    pub fn new(handle: Nl80211Handle) -> Self {
        Nl80211WiphyHandle(handle)
    }

    /// Retrieve the wireless interfaces
    /// (equivalent to `iw phy`)
    pub fn get(&mut self) -> Nl80211WiphyGetRequest {
        Nl80211WiphyGetRequest::new(self.0.clone())
    }
}
