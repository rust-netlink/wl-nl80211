// SPDX-License-Identifier: MIT

use netlink_packet_utils::nla::Nla;

use crate::{
    Nl80211Attr, Nl80211AttrsBuilder, Nl80211Handle, Nl80211SurveyGetRequest,
};

pub struct Nl80211SurveyHandle(Nl80211Handle);

#[derive(Debug)]
pub struct Nl80211Survey;

impl Nl80211Survey {
    /// Perform a survey dump
    pub fn new(if_index: u32) -> Nl80211AttrsBuilder<Self> {
        Nl80211AttrsBuilder::<Self>::new().if_index(if_index)
    }
}

impl Nl80211AttrsBuilder<Nl80211Survey> {
    /// Request overall radio statistics to be returned along with other survey
    /// data
    pub fn radio(self, value: bool) -> Self {
        if value {
            self.replace(Nl80211Attr::SurveyRadioStats)
        } else {
            self.remove(Nl80211Attr::SurveyRadioStats.kind())
        }
    }
}

impl Nl80211SurveyHandle {
    pub fn new(handle: Nl80211Handle) -> Self {
        Self(handle)
    }

    /// Retrieve the survey info
    /// (equivalent to `iw dev DEV survey dump`)
    pub fn dump(
        &mut self,
        attributes: Vec<Nl80211Attr>,
    ) -> Nl80211SurveyGetRequest {
        Nl80211SurveyGetRequest::new(self.0.clone(), attributes)
    }
}
