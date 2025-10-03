// SPDX-License-Identifier: MIT

use crate::{
    Nl80211Attr, Nl80211AttrsBuilder, Nl80211Handle,
    Nl80211InterfaceDeleteRequest, Nl80211InterfaceGetRequest,
    Nl80211InterfaceNewRequest, Nl80211InterfaceSetRequest,
    Nl80211InterfaceType,
};

pub struct Nl80211InterfaceHandle(Nl80211Handle);

#[derive(Debug)]
pub struct Nl80211Interface;

impl Nl80211Interface {
    /// Change properties of the interface
    pub fn new(if_index: u32) -> Nl80211AttrsBuilder<Self> {
        Nl80211AttrsBuilder::<Self>::new().if_index(if_index)
    }
}

impl Nl80211AttrsBuilder<Nl80211Interface> {
    /// Change the interface type
    /// (equivalent to `iw dev type <type>`)
    pub fn interface_type(self, r#type: Nl80211InterfaceType) -> Self {
        self.replace(Nl80211Attr::IfType(r#type))
    }
}

/// Builder for attributes used in  [`Nl80211InterfaceHandle::add`]
#[derive(Debug)]
pub struct Nl80211NewInterface;

impl Nl80211NewInterface {
    /// Construct a builder with the required attrs for
    /// [`Nl80211InterfaceHandle::add`]
    pub fn new(
        wiphy_id: u32,
        if_type: Nl80211InterfaceType,
        if_name: String,
    ) -> Nl80211AttrsBuilder<Self> {
        Nl80211AttrsBuilder::<Self>::new()
            .replace(Nl80211Attr::Wiphy(wiphy_id))
            .replace(Nl80211Attr::IfType(if_type))
            .replace(Nl80211Attr::IfName(if_name))
    }
}

impl Nl80211InterfaceHandle {
    pub fn new(handle: Nl80211Handle) -> Self {
        Nl80211InterfaceHandle(handle)
    }

    /// Retrieve the wireless interfaces
    /// (equivalent to `iw dev`)
    pub fn get(
        &mut self,
        attributes: Vec<Nl80211Attr>,
    ) -> Nl80211InterfaceGetRequest {
        Nl80211InterfaceGetRequest::new(self.0.clone(), attributes)
    }

    /// Set wireless interfaces attributes
    pub fn set(
        &mut self,
        attributes: Vec<Nl80211Attr>,
    ) -> Nl80211InterfaceSetRequest {
        Nl80211InterfaceSetRequest::new(self.0.clone(), attributes)
    }

    /// Add a new wireless interface.
    ///
    /// To construct `attributes` via a builder, see [`Nl80211NewInterface`].
    ///
    /// Per [nl80211.h](https://github.com/torvalds/linux/blob/v6.17/include/uapi/linux/nl80211.h#L374),
    /// the required attributes are:.
    ///
    /// - [`Nl80211Attr::Wiphy`]
    /// - [`Nl80211Attr::IfType`]
    /// - [`Nl80211Attr::IfName`]
    pub fn add(
        &mut self,
        attributes: Vec<Nl80211Attr>,
    ) -> Nl80211InterfaceNewRequest {
        Nl80211InterfaceNewRequest::new(self.0.clone(), attributes)
    }

    /// Delete a wireless interface.
    ///
    /// To construct `attributes` via a builder, see [`Nl80211Interface`].
    ///
    /// Per [nl80211.h](https://github.com/torvalds/linux/blob/v6.17/include/uapi/linux/nl80211.h#L380),
    /// the required attributes are:
    ///
    /// - [`Nl80211Attr::IfIndex`]  (see also [`Nl80211AttrsBuilder::if_index`])
    pub fn delete(
        &mut self,
        attributes: Vec<Nl80211Attr>,
    ) -> Nl80211InterfaceDeleteRequest {
        Nl80211InterfaceDeleteRequest::new(self.0.clone(), attributes)
    }
}
