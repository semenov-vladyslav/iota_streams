use iota_streams_core::{
    async_trait,
    prelude::{Arc, Box, Mutex, Rc, Vec},
    Result,
};

use core::{
    cell::RefCell,
    marker::{Send, Sync}
};


#[async_trait(?Send)]
pub trait TransportDetails<Link>
where
    Link: Send + Sync,
{
    type Details;
    async fn get_link_details(&mut self, link: &Link) -> Result<Self::Details>;
}

#[async_trait(?Send)]
pub trait TransportOptions {
    type SendOptions;
    async fn get_send_options(&self) -> Self::SendOptions;
    async fn set_send_options(&mut self, opt: Self::SendOptions);

    type RecvOptions;
    async fn get_recv_options(&self) -> Self::RecvOptions;
    async fn set_recv_options(&mut self, opt: Self::RecvOptions);
}

/// Network transport abstraction.
/// Parametrized by the type of message links.
/// Message link is used to identify/locate a message (eg. like URL for HTTP).
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

/*#[cfg(feature = "wasm-client")]
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
}*/


pub type SharedTransport<T> = Rc<RefCell<T>>;

pub fn new_shared_transport<T>(tsp: T) -> Rc<RefCell<T>> {
    Rc::new(RefCell::new(tsp))
}

//#[cfg(not(feature = "wasm-client"))]
#[async_trait(?Send)]
impl<Tsp: TransportOptions + Send + Sync> TransportOptions for Arc<Mutex<Tsp>>
where
    <Tsp as TransportOptions>::SendOptions: Send + Sync,
    <Tsp as TransportOptions>::RecvOptions: Send + Sync,
{
    type SendOptions = <Tsp as TransportOptions>::SendOptions;
    async fn get_send_options(&self) -> Self::SendOptions {
        (&*self).lock().get_send_options().await
    }
    async fn set_send_options(&mut self, opt: Self::SendOptions) {
        (&*self).lock().set_send_options(opt).await
    }

    type RecvOptions = <Tsp as TransportOptions>::RecvOptions;
    async fn get_recv_options(&self) -> Self::RecvOptions {
        (&*self).lock().get_recv_options().await
    }
    async fn set_recv_options(&mut self, opt: Self::RecvOptions) {
        (&*self).lock().set_recv_options(opt).await
    }
}

/*#[cfg(feature = "wasm-client")]
#[async_trait(?Send)]
impl<Tsp: TransportOptions + Send + Sync> TransportOptions for Rc<RefCell<Tsp>>
    where
        <Tsp as TransportOptions>::SendOptions: Send + Sync,
        <Tsp as TransportOptions>::RecvOptions: Send + Sync,
{
    type SendOptions = <Tsp as TransportOptions>::SendOptions;
    async fn get_send_options(&self) -> Self::SendOptions {
        (&*self).lock().get_send_options().await
    }
    async fn set_send_options(&mut self, opt: Self::SendOptions) {
        (&*self).lock().set_send_options(opt).await
    }

    type RecvOptions = <Tsp as TransportOptions>::RecvOptions;
    async fn get_recv_options(&self) -> Self::RecvOptions {
        (&*self).lock().get_recv_options().await
    }
    async fn set_recv_options(&mut self, opt: Self::RecvOptions) {
        (&*self).lock().set_recv_options(opt).await
    }
}*/


//#[cfg(not(feature = "wasm-client"))]
#[async_trait(?Send)]
impl<Link, Tsp: TransportDetails<Link> + Send + Sync> TransportDetails<Link> for Arc<Mutex<Tsp>>
where
    Link: 'static + core::marker::Send + core::marker::Sync,
{
    type Details = <Tsp as TransportDetails<Link>>::Details;
    async fn get_link_details(&mut self, link: &Link) -> Result<Self::Details> {
        (&*self).lock().get_link_details(link).await
    }
}

/*#[cfg(feature = "wasm-client")]
#[async_trait(?Send)]
impl<Link, Tsp: TransportDetails<Link>> TransportDetails<Link> for Rc<RefCell<Tsp>>
    where
        Link: 'static + core::marker::Send + core::marker::Sync,
{
    type Details = <Tsp as TransportDetails<Link>>::Details;
    async fn get_link_details(&mut self, link: &Link) -> Result<Self::Details> {
        (&*self).borrow_mut().get_link_details(link)
    }
}*/

//#[cfg(not(feature = "wasm-client"))]
#[async_trait(?Send)]
impl<Link, Msg, Tsp: Transport<Link, Msg> + Send + Sync> Transport<Link, Msg> for Arc<Mutex<Tsp>>
where
    Link: 'static + core::marker::Send + core::marker::Sync,
    Msg: 'static + core::marker::Send + core::marker::Sync,
    Tsp: core::marker::Send + core::marker::Sync,
    <Tsp as TransportOptions>::SendOptions: Send + Sync,
    <Tsp as TransportOptions>::RecvOptions: Send + Sync,
{
    // Send a message.
    async fn send_message(&mut self, msg: &Msg) -> Result<()> {
        (&*self).lock().send_message(msg).await
    }

    // Receive messages with default options.
    async fn recv_messages(&mut self, link: &Link) -> Result<Vec<Msg>> {
        (&*self).lock().recv_messages(link).await
    }

    // Receive a message with default options.
    async fn recv_message(&mut self, link: &Link) -> Result<Msg> {
        (&*self).lock().recv_message(link).await
    }
}

/*#[cfg(feature = "wasm-client")]
#[async_trait(?Send)]
impl<Link, Msg, Tsp: Transport<Link, Msg> + Send + Sync> Transport<Link, Msg> for Rc<RefCell<Tsp>>
    where
        Link: 'static + core::marker::Send + core::marker::Sync,
        Msg: 'static + core::marker::Send + core::marker::Sync,
        Tsp: core::marker::Send + core::marker::Sync,
        <Tsp as TransportOptions>::SendOptions: Send + Sync,
        <Tsp as TransportOptions>::RecvOptions: Send + Sync,
{
    // Send a message.
    async fn send_message(&mut self, msg: &Msg) -> Result<()> {
        (&*self).lock().send_message(msg).await
    }

    // Receive messages with default options.
    async fn recv_messages(&mut self, link: &Link) -> Result<Vec<Msg>> {
        (&*self).lock().recv_messages(link).await
    }

    // Receive a message with default options.
    async fn recv_message(&mut self, link: &Link) -> Result<Msg> {
        (&*self).lock().recv_message(link).await
    }
}*/

pub type MultiThreadTransport<T> = Arc<Mutex<T>>;

pub fn new_multi_thread_transport<T>(tsp: T) -> Arc<Mutex<T>> {
    Arc::new(Mutex::new(tsp))
}

mod bucket;
pub use bucket::BucketTransport;
use iota_streams_core::try_or;


#[cfg(feature = "tangle")]
pub mod tangle;
