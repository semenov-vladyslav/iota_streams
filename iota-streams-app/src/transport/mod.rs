use iota_streams_core::Result;

use core::cell::RefCell;

#[cfg(not(feature = "sync-client"))]
use iota_streams_core::async_trait;
#[cfg(not(feature = "sync-client"))]
use atomic_refcell::AtomicRefCell;
#[cfg(not(feature = "sync-client"))]
use core::marker::{
    Send,
    Sync,
};
#[cfg(not(feature = "sync-client"))]
use iota_streams_core::prelude::{
    Arc,
    Box,
};

#[cfg(feature = "sync-client")]
use iota_streams_core::prelude::ToString;

use iota_streams_core::prelude::{
    Rc,
    Vec,
};

#[cfg(feature = "sync-client")]
pub trait TransportDetails<Link> {
    type Details;
    fn get_link_details(&mut self, link: &Link) -> Result<Self::Details>;
}

#[cfg(not(feature = "sync-client"))]
#[async_trait(?Send)]
pub trait TransportDetails<Link>
where
    Link: Send + Sync,
{
    type Details;
    async fn get_link_details(&mut self, link: &Link) -> Result<Self::Details>;
}

pub trait TransportOptions {
    type SendOptions;
    fn get_send_options(&self) -> Self::SendOptions;
    fn set_send_options(&mut self, opt: Self::SendOptions);

    type RecvOptions;
    fn get_recv_options(&self) -> Self::RecvOptions;
    fn set_recv_options(&mut self, opt: Self::RecvOptions);
}

/// Network transport abstraction.
/// Parametrized by the type of message links.
/// Message link is used to identify/locate a message (eg. like URL for HTTP).
#[cfg(feature = "sync-client")]
pub trait Transport<Link: Debug + Display, Msg>: TransportOptions + TransportDetails<Link> {
    /// Send a message with default options.
    fn send_message(&mut self, msg: &Msg) -> Result<()>;

    /// Receive messages with default options.
    fn recv_messages(&mut self, link: &Link) -> Result<Vec<Msg>>;

    /// Receive a message with default options.
    fn recv_message(&mut self, link: &Link) -> Result<Msg> {
        let mut msgs = self.recv_messages(link)?;
        if let Some(msg) = msgs.pop() {
            try_or!(msgs.is_empty(), MessageNotUnique(link.to_string()))?;
            Ok(msg)
        } else {
            err!(MessageLinkNotFound(link.to_string()))
        }
    }
}

#[cfg(not(feature = "sync-client"))]
#[async_trait(?Send)]
pub trait Transport<Link, Msg>: TransportOptions + TransportDetails<Link>
where
    Link: Send + Sync,
    Msg: Send + Sync,
{
    /// Send a message with default options.
    async fn send_message(&mut self, msg: &Msg) -> Result<()>;

    /// Receive messages with default options.
    async fn recv_messages(&mut self, link: &Link) -> Result<Vec<Msg>>;

    /// Receive a message with default options.
    async fn recv_message(&mut self, link: &Link) -> Result<Msg>;
    // For some reason compiler requires (Msg: `async_trait) lifetime bound for this default implementation.
    // {
    // let mut msgs = self.recv_messages(link).await?;
    // if let Some(msg) = msgs.pop() {
    // ensure!(msgs.is_empty(), "More than one message found.");
    // Ok(msg)
    // } else {
    // err!()
    // }
    // }
}

impl<Tsp: TransportOptions> TransportOptions for Rc<RefCell<Tsp>> {
    type SendOptions = <Tsp as TransportOptions>::SendOptions;
    fn get_send_options(&self) -> Self::SendOptions {
        (&*self).borrow().get_send_options()
    }
    fn set_send_options(&mut self, opt: Self::SendOptions) {
        (&*self).borrow_mut().set_send_options(opt)
    }

    type RecvOptions = <Tsp as TransportOptions>::RecvOptions;
    fn get_recv_options(&self) -> Self::RecvOptions {
        (&*self).borrow().get_recv_options()
    }
    fn set_recv_options(&mut self, opt: Self::RecvOptions) {
        (&*self).borrow_mut().set_recv_options(opt)
    }
}

#[cfg(feature = "sync-client")]
impl<Tsp: TransportDetails<Link>, Link> TransportDetails<Link> for Rc<RefCell<Tsp>> {
    type Details = <Tsp as TransportDetails<Link>>::Details;
    fn get_link_details(&mut self, link: &Link) -> Result<Self::Details> {
        (&*self).borrow_mut().get_link_details(link)
    }
}

#[cfg(feature = "sync-client")]
impl<Link: Debug + Display, Msg, Tsp: Transport<Link, Msg>> Transport<Link, Msg> for Rc<RefCell<Tsp>> {
    /// Send a message.
    fn send_message(&mut self, msg: &Msg) -> Result<()> {
        match (&*self).try_borrow_mut() {
            Ok(mut tsp) => tsp.send_message(msg),
            Err(err) => Err(wrapped_err!(TransportNotAvailable, WrappedError(err))),
        }
    }

    /// Receive messages with default options.
    fn recv_messages(&mut self, link: &Link) -> Result<Vec<Msg>> {
        match (&*self).try_borrow_mut() {
            Ok(mut tsp) => tsp.recv_messages(link),
            Err(err) => Err(wrapped_err!(TransportNotAvailable, WrappedError(err))),
        }
    }

    /// Receive a message with default options.
    fn recv_message(&mut self, link: &Link) -> Result<Msg> {
        match (&*self).try_borrow_mut() {
            Ok(mut tsp) => tsp.recv_message(link),
            Err(err) => Err(wrapped_err!(TransportNotAvailable, WrappedError(err))),
        }
    }
}

#[cfg(feature = "sync-client")]
pub type SharedTransport<T> = Rc<RefCell<T>>;

#[cfg(feature = "sync-client")]
pub fn new_shared_transport<T>(tsp: T) -> Rc<RefCell<T>> {
    Rc::new(RefCell::new(tsp))
}

#[cfg(not(feature = "sync-client"))]
impl<Tsp: TransportOptions> TransportOptions for Arc<AtomicRefCell<Tsp>> {
    type SendOptions = <Tsp as TransportOptions>::SendOptions;
    fn get_send_options(&self) -> Self::SendOptions {
        (&*self).borrow().get_send_options()
    }
    fn set_send_options(&mut self, opt: Self::SendOptions) {
        (&*self).borrow_mut().set_send_options(opt)
    }

    type RecvOptions = <Tsp as TransportOptions>::RecvOptions;
    fn get_recv_options(&self) -> Self::RecvOptions {
        (&*self).borrow().get_recv_options()
    }
    fn set_recv_options(&mut self, opt: Self::RecvOptions) {
        (&*self).borrow_mut().set_recv_options(opt)
    }
}

// The impl below is too restrictive: Link and Msg require 'async_trait life-time, Tsp is Sync + Send.
// #[cfg(not(feature = "sync-client"))]
// #[async_trait]
// impl<Link, Msg, Tsp: Transport<Link, Msg>> Transport<Link, Msg> for Arc<AtomicRefCell<Tsp>> where
// Link: 'static + core::marker::Send + core::marker::Sync,
// Msg: 'static + core::marker::Send + core::marker::Sync,
// Tsp: core::marker::Send + core::marker::Sync,
// {
// Send a message.
// async fn send_message(&mut self, msg: &Msg) -> Result<()> {
// (&*self).borrow_mut().send_message(msg).await
// }
//
// Receive messages with default options.
// async fn recv_messages(&mut self, link: &Link) -> Result<Vec<Msg>> {
// (&*self).borrow_mut().recv_messages(link).await
// }
//
// Receive a message with default options.
// async fn recv_message(&mut self, link: &Link) -> Result<Msg> {
// (&*self).borrow_mut().recv_message(link).await
// }
// }

#[cfg(not(feature = "sync-client"))]
pub type SharedTransport<T> = Arc<AtomicRefCell<T>>;

#[cfg(not(feature = "sync-client"))]
pub fn new_shared_transport<T>(tsp: T) -> Arc<AtomicRefCell<T>> {
    Arc::new(AtomicRefCell::new(tsp))
}

mod bucket;
pub use bucket::BucketTransport;

#[cfg(feature = "sync-client")]
use core::fmt::{
    Debug,
    Display,
};

use iota_streams_core::try_or;

#[cfg(feature = "sync-client")]
use iota_streams_core::{
    err,
    wrapped_err,
    Errors::{
        MessageLinkNotFound,
        MessageNotUnique,
        TransportNotAvailable,
    },
    WrappedError,
};

#[cfg(feature = "tangle")]
pub mod tangle;
