// SPDX-License-Identifier: MIT

use crate::{
    Nl80211Attr, Nl80211AttrsBuilder, Nl80211ChannelSwitchRequest,
    Nl80211ChannelWidth, Nl80211Handle, Nl80211HtWiphyChannelType,
    Nl80211WiphyGetRequest,
};

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

    pub fn set(
        &mut self,
        attributes: Vec<Nl80211Attr>,
    ) -> Nl80211ChannelSwitchRequest {
        Nl80211ChannelSwitchRequest::new(self.0.clone(), attributes)
    }
}

#[derive(Debug)]
pub struct Nl80211Channel;

impl Nl80211Channel {
    pub fn new(if_index: u32) -> Nl80211AttrsBuilder<Self> {
        Nl80211AttrsBuilder::<Self>::new().if_index(if_index)
    }
}

impl Nl80211AttrsBuilder<Nl80211Channel> {
    pub fn frequency(self, value: u32) -> Self {
        self.replace(Nl80211Attr::WiphyFreq(value))
    }

    pub fn frequency_offset(self, value: u32) -> Self {
        self.replace(Nl80211Attr::WiphyFreqOffset(value))
    }

    pub fn channel_width(self, value: Nl80211ChannelWidth) -> Self {
        self.replace(Nl80211Attr::ChannelWidth(value))
    }

    pub fn channel_type(self, value: Nl80211HtWiphyChannelType) -> Self {
        self.replace(Nl80211Attr::WiphyChannelType(value))
    }

    pub fn center_frequency(self, value: u32) -> Self {
        self.replace(Nl80211Attr::CenterFreq1(value))
    }
}
