// SPDX-License-Identifier: MIT

use std::collections::HashMap;
use std::marker::PhantomData;

use netlink_packet_utils::nla::Nla;

use crate::Nl80211Attr;

#[derive(Debug)]
pub struct Nl80211AttrsBuilder<T> {
    attribute_map: HashMap<u16, Vec<Nl80211Attr>>,
    _phantom: PhantomData<T>,
}

impl<T> Default for Nl80211AttrsBuilder<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Nl80211AttrsBuilder<T> {
    pub fn new() -> Self {
        Self {
            attribute_map: HashMap::new(),
            _phantom: PhantomData,
        }
    }

    /// Add Nl80211Attr by removing other Nl80211Attr holding the same
    /// Nl80211Attr.kind()
    pub fn replace(self, attr: Nl80211Attr) -> Self {
        let mut ret = self;
        ret.attribute_map.insert(attr.kind(), vec![attr]);
        ret
    }

    pub fn append(self, attr: Nl80211Attr) -> Self {
        let mut ret = self;
        ret.attribute_map.entry(attr.kind()).or_default().push(attr);
        ret
    }

    pub fn remove(self, kind: u16) -> Self {
        let mut ret = self;
        ret.attribute_map.remove(&kind);
        ret
    }

    pub fn build(self) -> Vec<Nl80211Attr> {
        let mut data = self;
        let mut ret: Vec<Nl80211Attr> = Vec::new();
        for (_, mut v) in data.attribute_map.drain() {
            ret.append(&mut v)
        }

        ret.sort_unstable_by_key(|a| a.kind());
        ret
    }

    pub fn if_index(self, if_index: u32) -> Self {
        self.replace(Nl80211Attr::IfIndex(if_index))
    }

    pub fn ssid(self, ssid: &str) -> Self {
        self.append(Nl80211Attr::Ssid(ssid.to_string()))
    }
}
