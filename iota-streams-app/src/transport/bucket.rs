use super::*;
use crate::message::LinkedMessage;
use core::hash;

use iota_streams_core::{
    err,
    prelude::{
        string::ToString,
        HashMap,
    },
    Errors::MessageLinkNotFound,
};

use iota_streams_core::{
    async_trait,
    prelude::Box,
    Errors::MessageNotUnique,
};

#[derive(Clone)]
pub struct BucketTransport<Link, Msg> {
    bucket: HashMap<Link, Vec<Msg>>,
}

impl<Link, Msg> Default for BucketTransport<Link, Msg>
where
    Link: Eq + hash::Hash,
{
    fn default() -> Self {
        Self { bucket: HashMap::new() }
    }
}

impl<Link, Msg> BucketTransport<Link, Msg>
where
    Link: Eq + hash::Hash,
{
    pub fn new() -> Self {
        Self { bucket: HashMap::new() }
    }
}

#[async_trait(?Send)]
impl<Link: Send + Sync, Msg: Send + Sync> TransportOptions for BucketTransport<Link, Msg> {
    type SendOptions = ();
    async fn get_send_options(&self) {}
    async fn set_send_options(&mut self, _opt: ()) {}

    type RecvOptions = ();
    async fn get_recv_options(&self) {}
    async fn set_recv_options(&mut self, _opt: ()) {}
}

#[async_trait(?Send)]
impl<Link, Msg> Transport<Link, Msg> for BucketTransport<Link, Msg>
where
    Link: Eq + hash::Hash + Clone + core::marker::Send + core::marker::Sync + core::fmt::Display,
    Msg: LinkedMessage<Link> + Clone + core::marker::Send + core::marker::Sync,
{
    async fn send_message(&mut self, msg: &Msg) -> Result<()> {
        if let Some(msgs) = self.bucket.get_mut(msg.link()) {
            msgs.push(msg.clone());
            Ok(())
        } else {
            self.bucket.insert(msg.link().clone(), vec![msg.clone()]);
            Ok(())
        }
    }

    async fn recv_messages(&mut self, link: &Link) -> Result<Vec<Msg>> {
        if let Some(msgs) = self.bucket.get(link) {
            Ok(msgs.clone())
        } else {
            err!(MessageLinkNotFound(link.to_string()))
        }
    }

    async fn recv_message(&mut self, link: &Link) -> Result<Msg> {
        let mut msgs = self.recv_messages(link).await?;
        if let Some(msg) = msgs.pop() {
            try_or!(msgs.is_empty(), MessageNotUnique(link.to_string())).unwrap();
            Ok(msg)
        } else {
            err!(MessageLinkNotFound(link.to_string()))?
        }
    }
}

#[async_trait(?Send)]
impl<Link, Msg> TransportDetails<Link> for BucketTransport<Link, Msg>
where
    Link: Eq + hash::Hash + Clone + core::marker::Send + core::marker::Sync + core::fmt::Display,
    Msg: Send + Sync,
{
    type Details = ();
    async fn get_link_details(&mut self, _opt: &Link) -> Result<Self::Details> {
        Ok(())
    }
}
