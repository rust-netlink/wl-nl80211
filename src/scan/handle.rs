// SPDX-License-Identifier: MIT

use crate::{Nl80211Handle, Nl80211ScanGetRequest};

pub struct Nl80211ScanHandle(Nl80211Handle);

impl Nl80211ScanHandle {
    pub fn new(handle: Nl80211Handle) -> Self {
        Nl80211ScanHandle(handle)
    }

    /// Retrieve the current scan data
    /// (equivalent to `iw dev DEVICE scan dump`)
    pub fn dump(&mut self, if_index: u32) -> Nl80211ScanGetRequest {
        Nl80211ScanGetRequest::new(self.0.clone(), if_index)
    }
}
