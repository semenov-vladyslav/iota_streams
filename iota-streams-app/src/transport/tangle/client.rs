use futures::executor::block_on;

#[cfg(feature = "async")]
use core::cell::RefCell;
use core::fmt;
#[cfg(feature = "async")]
use iota_streams_core::prelude::Rc;

pub use iota_client;

use iota_client::{
    bee_rest_api::types::responses::MessageMetadataResponse,
    MilestoneResponse,
};

use iota_client::bee_message::{
    payload::Payload,
    Message,
};

use iota_streams_core::{
    err,
    prelude::Vec,
    try_or,
    wrapped_err,
    Errors::*,
    Result,
    WrappedError,
};

use crate::{
    message::BinaryMessage,
    transport::{
        tangle::*,
        *,
    },
};

use futures::future::join_all;

use iota_streams_core::prelude::String;

/// Options for the user Client
#[derive(Clone)]
pub struct SendOptions {
    pub url: String,
    pub local_pow: bool,
}

impl Default for SendOptions {
    fn default() -> Self {
        Self {
            url: "https://chrysalis-nodes.iota.org".to_string(),
            local_pow: true,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Details {
    pub metadata: MessageMetadataResponse,
    pub milestone: Option<MilestoneResponse>,
}

impl fmt::Display for Details {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<metadata={:?}, milestone={:?}>", self.metadata, self.milestone)
    }
}

fn handle_client_result<T>(result: iota_client::Result<T>) -> Result<T> {
    result.map_err(|err| wrapped_err!(ClientOperationFailure, WrappedError(err)))
}

/// Reconstruct Streams Message from bundle.
///
/// The input bundle is not checked (for validity of the hash, consistency of indices, etc.).
/// Checked bundles are returned by `client.get_message().index`.
pub fn msg_from_tangle_message<F>(message: &Message, link: &TangleAddress) -> Result<TangleMessage<F>> {
    if let Some(Payload::Indexation(i)) = message.payload().as_ref() {
        let mut bytes = Vec::<u8>::new();
        for b in i.data() {
            bytes.push(*b);
        }

        let binary = BinaryMessage::new(link.clone(), TangleAddress::default(), bytes.into());
        // TODO get timestamp
        let timestamp: u64 = 0;

        Ok(TangleMessage { binary, timestamp })
    } else {
        err!(BadMessagePayload)
    }
}

async fn get_messages(client: &iota_client::Client, link: &TangleAddress) -> Result<Vec<Message>> {
    let hash = link.to_msg_index();
    let msg_ids = handle_client_result(client.get_message().index(hash).await)?;
    try_or!(!msg_ids.is_empty(), IndexNotFound)?;

    let msgs = join_all(
        msg_ids
            .iter()
            .map(|msg| async move { handle_client_result(client.get_message().data(msg).await) }),
    )
    .await
    .into_iter()
    .filter_map(|msg| msg.ok())
    .collect::<Vec<_>>();
    try_or!(!msgs.is_empty(), MessageContentsNotFound)?;
    Ok(msgs)
}

/// Send a message to the Tangle using a node client
pub async fn async_send_message_with_options<F>(client: &iota_client::Client, msg: &TangleMessage<F>) -> Result<()> {
    let hash = msg.binary.link.to_msg_index();

    // TODO: Get rid of copy caused by to_owned
    client
        .message()
        .with_index(hash)
        .with_data(msg.binary.body.bytes.clone())
        .finish()
        .await?;
    Ok(())
}

/// Retrieve a message from the tangle using a node client
pub async fn async_recv_messages<F>(
    client: &iota_client::Client,
    link: &TangleAddress,
) -> Result<Vec<TangleMessage<F>>> {
    match get_messages(client, link).await {
        Ok(txs) => Ok(txs
            .iter()
            .filter_map(|b| msg_from_tangle_message(b, link).ok()) // Ignore errors
            .collect()),
        Err(_) => Ok(Vec::new()), // Just ignore the error?
    }
}

/// Retrieve details of a link from the tangle using a node client
pub async fn async_get_link_details(client: &iota_client::Client, link: &TangleAddress) -> Result<Details> {
    let hash = link.to_msg_index();
    let msg_ids = handle_client_result(client.get_message().index(hash).await)?;
    try_or!(!msg_ids.is_empty(), IndexNotFound)?;

    let metadata = handle_client_result(client.get_message().metadata(&msg_ids[0]).await)?;

    let mut milestone = None;
    if let Some(ms_index) = metadata.referenced_by_milestone_index {
        milestone = Some(handle_client_result(client.get_milestone(ms_index).await)?);
    }

    Ok(Details { metadata, milestone })
}

/// Synchronised - Send message to the tangle using a node client
#[cfg(not(feature = "async"))]
pub fn sync_send_message_with_options<F>(client: &iota_client::Client, msg: &TangleMessage<F>) -> Result<()> {
    block_on(async_send_message_with_options(client, msg))
}

/// Synchronised - Retrieve a message from the tangle using a node client
#[cfg(not(feature = "async"))]
pub fn sync_recv_messages<F>(client: &iota_client::Client, link: &TangleAddress) -> Result<Vec<TangleMessage<F>>> {
    block_on(async_recv_messages(client, link))
}

/// Synchronised - Retrieve details of a link from the tangle using a node client
#[cfg(not(feature = "async"))]
pub fn sync_get_link_details(client: &iota_client::Client, link: &TangleAddress) -> Result<Details> {
    block_on(async_get_link_details(client, link))
}

/// Stub type for iota_client::Client.  Removed: Copy, Default, Clone
pub struct Client {
    send_opt: SendOptions,
    client: iota_client::Client,
}

impl Default for Client {
    // Creates a new instance which links to a node on localhost:14265
    fn default() -> Self {
        Self {
            send_opt: SendOptions::default(),
            client: block_on(
                iota_client::ClientBuilder::new()
                    .with_node("http://localhost:14265")
                    .unwrap()
                    .finish(),
            )
            .unwrap(),
        }
    }
}

impl Client {
    // Create an instance of Client with a ready client and its send options
    pub fn new(options: SendOptions, client: iota_client::Client) -> Self {
        Self {
            send_opt: options,
            client,
        }
    }

    // Create an instance of Client with a node pointing to the given URL
    pub fn new_from_url(url: &str) -> Self {
        Self {
            send_opt: SendOptions {
                url: url.to_string(),
                ..Default::default()
            },
            client: block_on(
                iota_client::ClientBuilder::new()
                    .with_node(url)
                    .unwrap()
                    .with_local_pow(false)
                    .finish(),
            )
            .unwrap(),
        }
    }
}

impl Clone for Client {
    fn clone(&self) -> Self {
        Self {
            send_opt: self.send_opt.clone(),
            client: block_on(
                iota_client::ClientBuilder::new()
                    .with_node(&self.send_opt.url)
                    .unwrap()
                    .with_local_pow(self.send_opt.local_pow)
                    .finish(),
            )
            .unwrap(),
        }
    }
}

impl TransportOptions for Client {
    type SendOptions = SendOptions;
    fn get_send_options(&self) -> SendOptions {
        self.send_opt.clone()
    }
    fn set_send_options(&mut self, opt: SendOptions) {
        self.send_opt = opt;

        // TODO
        // self.client.set_send_options()
    }

    type RecvOptions = ();
    fn get_recv_options(&self) {}
    fn set_recv_options(&mut self, _opt: ()) {}
}

#[cfg(not(feature = "async"))]
impl TransportDetails<TangleAddress> for Client {
    type Details = Details;
    fn get_link_details(&mut self, link: &TangleAddress) -> Result<Self::Details> {
        sync_get_link_details(&self.client, link)
    }
}

#[cfg(not(feature = "async"))]
impl<F> Transport<TangleAddress, TangleMessage<F>> for Client {
    /// Send a Streams message over the Tangle with the current timestamp and default SendOptions.
    fn send_message(&mut self, msg: &TangleMessage<F>) -> Result<()> {
        sync_send_message_with_options(&self.client, msg)
    }

    /// Receive a message.
    fn recv_messages(&mut self, link: &TangleAddress) -> Result<Vec<TangleMessage<F>>> {
        sync_recv_messages(&self.client, link)
    }
}

#[cfg(feature = "async")]
#[async_trait(?Send)]
impl<F> Transport<TangleAddress, TangleMessage<F>> for Client
where
    F: 'static + core::marker::Send + core::marker::Sync,
{
    /// Send a Streams message over the Tangle with the current timestamp and default SendOptions.
    async fn send_message(&mut self, msg: &TangleMessage<F>) -> Result<()> {
        async_send_message_with_options(&self.client, msg).await
    }

    /// Receive a message.
    async fn recv_messages(&mut self, link: &TangleAddress) -> Result<Vec<TangleMessage<F>>> {
        async_recv_messages(&self.client, link).await
    }

    async fn recv_message(&mut self, link: &TangleAddress) -> Result<TangleMessage<F>> {
        let mut msgs = self.recv_messages(link).await?;
        if let Some(msg) = msgs.pop() {
            try_or!(msgs.is_empty(), MessageNotUnique(link.to_string()))?;
            Ok(msg)
        } else {
            err!(MessageLinkNotFound(link.to_string()))
        }
    }
}

#[cfg(feature = "async")]
#[async_trait(?Send)]
impl TransportDetails<TangleAddress> for Client {
    type Details = Details;
    async fn get_link_details(&mut self, link: &TangleAddress) -> Result<Self::Details> {
        async_get_link_details(&self.client, link).await
    }
}

#[cfg(feature = "async")]
#[async_trait(?Send)]
impl TransportDetails<TangleAddress> for Rc<RefCell<Client>> {
    type Details = Details;
    async fn get_link_details(&mut self, link: &TangleAddress) -> Result<Self::Details> {
        match (&*self).try_borrow_mut() {
            Ok(tsp) => async_get_link_details(&tsp.client, link).await,
            Err(err) => Err(wrapped_err!(TransportNotAvailable, WrappedError(err))),
        }
    }
}

// It's safe to impl async trait for Rc<RefCell<T>> targeting wasm as it's single-threaded.
#[cfg(feature = "async")]
#[async_trait(?Send)]
impl<F> Transport<TangleAddress, TangleMessage<F>> for Rc<RefCell<Client>>
where
    F: 'static + core::marker::Send + core::marker::Sync,
{
    /// Send a Streams message over the Tangle with the current timestamp and default SendOptions.
    async fn send_message(&mut self, msg: &TangleMessage<F>) -> Result<()> {
        match (&*self).try_borrow_mut() {
            Ok(tsp) => async_send_message_with_options(&tsp.client, msg).await,
            Err(_err) => err!(TransportNotAvailable),
        }
    }

    /// Receive a message.
    async fn recv_messages(&mut self, link: &TangleAddress) -> Result<Vec<TangleMessage<F>>> {
        match (&*self).try_borrow_mut() {
            Ok(tsp) => async_recv_messages(&tsp.client, link).await,
            Err(_err) => err!(TransportNotAvailable),
        }
    }

    async fn recv_message(&mut self, link: &TangleAddress) -> Result<TangleMessage<F>> {
        match (&*self).try_borrow_mut() {
            Ok(tsp) => {
                let mut msgs = async_recv_messages(&tsp.client, link).await?;
                if let Some(msg) = msgs.pop() {
                    try_or!(msgs.is_empty(), MessageNotUnique(link.msgid.to_string()))?;
                    Ok(msg)
                } else {
                    err!(MessageLinkNotFound(link.msgid.to_string()))
                }
            }
            Err(_err) => err!(TransportNotAvailable),
        }
    }
}
