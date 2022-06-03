// Rust
use alloc::{
    boxed::Box,
    format,
    string::{String, ToString},
    vec::Vec,
};
use core::fmt::{self, Debug, Formatter};

// 3rd-party
use anyhow::{anyhow, bail, ensure, Result};
use async_trait::async_trait;
use futures::{future, TryStreamExt};
use hashbrown::HashMap;
use rand::{rngs::StdRng, Rng, SeedableRng};

// IOTA
use crypto::keys::x25519;

// Streams
use lets::{
    address::{Address, AppAddr, MsgId},
    id::{Identifier, Identity, PermissionDuration, Permissioned, Psk, PskId},
    message::{
        ContentSizeof, ContentUnwrap, ContentWrap, Message as LetsMessage, PreparsedMessage, TransportMessage, HDF, PCF,
    },
    transport::Transport,
};
use spongos::{
    ddml::{
        commands::{sizeof, unwrap, wrap, Absorb, Commit, Mask, Squeeze},
        modifiers::External,
        types::{Mac, Maybe, NBytes, Size},
    },
    KeccakF1600, Spongos, SpongosRng,
};

// Local
use crate::{
    api::{
        cursor_store::CursorStore, message::Message, messages::Messages, send_response::SendResponse,
        user_builder::UserBuilder,
    },
    message::{announcement, keyload, message_types, signed_packet, subscription, tagged_packet, unsubscription},
};

const ANN_MESSAGE_NUM: usize = 0; // Announcement is always the first message of authors
const SUB_MESSAGE_NUM: usize = 0; // Subscription is always the first message of subscribers
const INIT_MESSAGE_NUM: usize = 1; // First non-reserved message number

#[derive(PartialEq, Eq, Default)]
struct State {
    /// Users' Identity information, contains keys and logic for signing and verification
    user_id: Option<Identity>,

    /// Address of the stream announcement message
    ///
    /// None if channel is not created or user is not subscribed.
    stream_address: Option<Address>,

    author_identifier: Option<Identifier>,

    /// Users' trusted public keys together with additional sequencing info: (msgid, seq_no).
    cursor_store: CursorStore,

    /// Mapping of trusted pre shared keys and identifiers
    psk_store: HashMap<PskId, Psk>,

    /// Mapping of exchange keys and identifiers
    exchange_keys: HashMap<Identifier, x25519::PublicKey>,

    spongos_store: HashMap<MsgId, Spongos>,
}

pub struct User<T> {
    transport: T,

    state: State,
}

impl User<()> {
    pub fn builder() -> UserBuilder<()> {
        UserBuilder::new()
    }
}

impl<T> User<T> {
    pub(crate) fn new<Psks>(user_id: Option<Identity>, psks: Psks, transport: T) -> Self
    where
        Psks: IntoIterator<Item = (PskId, Psk)>,
    {
        let cursor_store = CursorStore::new();
        let mut psk_store = HashMap::new();
        let mut exchange_keys = HashMap::new();

        // Store any pre shared keys
        psks.into_iter().for_each(|(pskid, psk)| {
            psk_store.insert(pskid, psk);
        });

        if let Some(id) = user_id.as_ref() {
            exchange_keys.insert(id.to_identifier(), id._ke_sk().public_key());
        }

        Self {
            transport,
            state: State {
                user_id,
                cursor_store,
                psk_store,
                exchange_keys,
                spongos_store: Default::default(),
                stream_address: None,
                author_identifier: None,
            },
        }
    }

    /// User's identifier
    pub fn identifier(&self) -> Result<Identifier> {
        self.identity().map(|id| id.to_identifier())
    }

    /// User Identity
    pub fn identity(&self) -> Result<&Identity> {
        self.state
            .user_id
            .as_ref()
            .ok_or_else(|| anyhow!("User does not have a stored identity"))
    }

    /// User's cursor
    fn cursor(&self) -> Option<usize> {
        self.identifier()
            .ok()
            .and_then(|id| self.state.cursor_store.get_cursor(&id))
    }

    fn next_cursor(&self) -> Result<usize> {
        self.cursor()
            .map(|c| c + 1)
            .ok_or_else(|| anyhow!("User is not a publisher"))
    }

    pub(crate) fn stream_address(&self) -> Option<Address> {
        self.state.stream_address
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub(crate) fn cursors(&self) -> impl Iterator<Item = (Identifier, usize)> + ExactSizeIterator + '_ {
        self.state.cursor_store.cursors()
    }

    pub fn subscribers(&self) -> impl Iterator<Item = Identifier> + Clone + '_ {
        self.state.exchange_keys.keys().copied()
    }

    fn should_store_cursor(&self, subscriber: &Permissioned<Identifier>) -> bool {
        let no_tracked_cursor = !self.state.cursor_store.is_cursor_tracked(subscriber.identifier());
        !subscriber.is_readonly() && no_tracked_cursor
    }

    pub fn add_subscriber(&mut self, subscriber: Identifier) -> bool {
        self.state
            .exchange_keys
            .insert(
                subscriber,
                subscriber
                    ._ke_pk()
                    .expect("subscriber must have an identifier from which an x25519 public key can be derived"),
            )
            .is_none()
    }

    pub fn remove_subscriber(&mut self, id: Identifier) -> bool {
        self.state.cursor_store.remove(&id) | self.state.exchange_keys.remove(&id).is_some()
    }

    pub fn add_psk(&mut self, psk: Psk) -> bool {
        self.state.psk_store.insert(psk.to_pskid(), psk).is_none()
    }

    pub fn remove_psk(&mut self, pskid: PskId) -> bool {
        self.state.psk_store.remove(&pskid).is_some()
    }

    pub(crate) async fn handle_message(&mut self, address: Address, msg: TransportMessage) -> Result<Message> {
        let preparsed = msg.parse_header().await?;
        match preparsed.header().message_type() {
            message_types::ANNOUNCEMENT => self.handle_announcement(address, preparsed).await,
            message_types::SUBSCRIPTION => self.handle_subscription(address, preparsed).await,
            message_types::UNSUBSCRIPTION => self.handle_unsubscription(address, preparsed).await,
            message_types::KEYLOAD => self.handle_keyload(address, preparsed).await,
            message_types::SIGNED_PACKET => self.handle_signed_packet(address, preparsed).await,
            message_types::TAGGED_PACKET => self.handle_tagged_packet(address, preparsed).await,
            unknown => Err(anyhow!("unexpected message type {}", unknown)),
        }
    }

    /// Bind Subscriber to the channel announced
    /// in the message.
    async fn handle_announcement(&mut self, address: Address, preparsed: PreparsedMessage) -> Result<Message> {
        // Check conditions
        if let Some(stream_address) = self.stream_address() {
            bail!(
                "cannot handle announcement: user is already connected to the stream {}",
                stream_address
            );
        }

        // From the point of view of cursor tracking, the message exists, regardless of the validity or
        // accessibility to its content. Therefore we must update the cursor of the publisher before
        // handling the message
        self.state
            .cursor_store
            .insert_cursor(preparsed.header().publisher(), INIT_MESSAGE_NUM);

        // Unwrap message
        let announcement = announcement::Unwrap::default();
        let (message, spongos) = preparsed.unwrap(announcement).await?;

        // Store spongos
        self.state.spongos_store.insert(address.relative(), spongos);

        // Store message content into stores
        let author_id = message.payload().content().author_id();
        let author_ke_pk = message.payload().content().author_ke_pk();
        self.state.exchange_keys.insert(author_id, author_ke_pk);
        self.state.stream_address = Some(address);
        self.state.author_identifier = Some(author_id);

        Ok(Message::from_lets_message(address, message))
    }
    async fn handle_subscription(&mut self, address: Address, preparsed: PreparsedMessage) -> Result<Message> {
        // Cursor is not stored, as cursor is only tracked for subscribers with write permissions

        // Unwrap message
        let linked_msg_address = preparsed.header().linked_msg_address().ok_or_else(|| {
            anyhow!("subscription messages must contain the address of the message they are linked to in the header")
        })?;
        let mut linked_msg_spongos = {
            if let Some(spongos) = self.state.spongos_store.get(&linked_msg_address).copied() {
                // Spongos must be copied because wrapping mutates it
                spongos
            } else {
                return Ok(Message::orphan(address, preparsed));
            }
        };
        let user_ke_sk = &self.identity()?._ke_sk();
        let subscription = subscription::Unwrap::new(&mut linked_msg_spongos, user_ke_sk);
        let (message, _spongos) = preparsed.unwrap(subscription).await?;

        // Store spongos
        // Subscription messages are never stored in spongos to maintain consistency about the view of the
        // set of messages of the stream between all the subscribers and across stateless recovers

        // Store message content into stores
        let subscriber_identifier = message.payload().content().subscriber_identifier();
        let subscriber_ke_pk = message.payload().content().subscriber_ke_pk();
        self.state.exchange_keys.insert(subscriber_identifier, subscriber_ke_pk);

        Ok(Message::from_lets_message(address, message))
    }

    async fn handle_unsubscription(&mut self, address: Address, preparsed: PreparsedMessage) -> Result<Message> {
        // Cursor is not stored, as user is unsubscribing

        // Unwrap message
        let linked_msg_address = preparsed.header().linked_msg_address().ok_or_else(|| {
            anyhow!("signed packet messages must contain the address of the message they are linked to in the header")
        })?;
        let mut linked_msg_spongos = {
            if let Some(spongos) = self.state.spongos_store.get(&linked_msg_address) {
                *spongos
            } else {
                return Ok(Message::orphan(address, preparsed));
            }
        };
        let unsubscription = unsubscription::Unwrap::new(&mut linked_msg_spongos);
        let (message, spongos) = preparsed.unwrap(unsubscription).await?;

        // Store spongos
        self.state.spongos_store.insert(address.relative(), spongos);

        // Store message content into stores
        self.remove_subscriber(message.payload().content().subscriber_identifier());

        Ok(Message::from_lets_message(address, message))
    }

    async fn handle_keyload(&mut self, address: Address, preparsed: PreparsedMessage) -> Result<Message> {
        // From the point of view of cursor tracking, the message exists, regardless of the validity or
        // accessibility to its content. Therefore we must update the cursor of the publisher before
        // handling the message
        self.state
            .cursor_store
            .insert_cursor(preparsed.header().publisher(), preparsed.header().sequence());

        // Unwrap message
        let author_identifier = self.state.author_identifier.ok_or_else(|| {
            anyhow!("before receiving keyloads one must have received the announcement of a stream first")
        })?;
        let stream_address = self
            .stream_address()
            .ok_or_else(|| anyhow!("before handling a keyload one must have received a stream announcement first"))?;
        let mut announcement_spongos = self
            .state
            .spongos_store
            .get(&stream_address.relative())
            .copied()
            .expect("a subscriber that has received an stream announcement must keep its spongos in store");

        // TODO: Remove Psk from Identity and Identifier, and manage it as a complementary permission
        let keyload = keyload::Unwrap::new(
            &mut announcement_spongos,
            self.state.user_id.as_ref(),
            author_identifier,
            &self.state.psk_store,
        );
        let (message, spongos) = preparsed.unwrap(keyload).await?;

        // Store spongos
        self.state.spongos_store.insert(address.relative(), spongos);

        // Store message content into stores
        for subscriber in &message.payload().content().subscribers {
            if self.should_store_cursor(subscriber) {
                self.state
                    .cursor_store
                    .insert_cursor(*subscriber.identifier(), INIT_MESSAGE_NUM);
            }
        }

        Ok(Message::from_lets_message(address, message))
    }

    async fn handle_signed_packet(&mut self, address: Address, preparsed: PreparsedMessage) -> Result<Message> {
        // From the point of view of cursor tracking, the message exists, regardless of the validity or
        // accessibility to its content. Therefore we must update the cursor of the publisher before
        // handling the message
        self.state
            .cursor_store
            .insert_cursor(preparsed.header().publisher(), preparsed.header().sequence());

        // Unwrap message
        let linked_msg_address = preparsed.header().linked_msg_address().ok_or_else(|| {
            anyhow!("signed packet messages must contain the address of the message they are linked to in the header")
        })?;
        let mut linked_msg_spongos = {
            if let Some(spongos) = self.state.spongos_store.get(&linked_msg_address).copied() {
                // Spongos must be copied because wrapping mutates it
                spongos
            } else {
                return Ok(Message::orphan(address, preparsed));
            }
        };
        let signed_packet = signed_packet::Unwrap::new(&mut linked_msg_spongos);
        let (message, spongos) = preparsed.unwrap(signed_packet).await?;

        // Store spongos
        self.state.spongos_store.insert(address.relative(), spongos);

        // Store message content into stores

        Ok(Message::from_lets_message(address, message))
    }

    async fn handle_tagged_packet(&mut self, address: Address, preparsed: PreparsedMessage) -> Result<Message> {
        // From the point of view of cursor tracking, the message exists, regardless of the validity or
        // accessibility to its content. Therefore we must update the cursor of the publisher before
        // handling the message
        self.state
            .cursor_store
            .insert_cursor(preparsed.header().publisher(), preparsed.header().sequence());

        // Unwrap message
        let linked_msg_address = preparsed.header().linked_msg_address().ok_or_else(|| {
            anyhow!("signed packet messages must contain the address of the message they are linked to in the header")
        })?;
        let mut linked_msg_spongos = {
            if let Some(spongos) = self.state.spongos_store.get(&linked_msg_address).copied() {
                // Spongos must be copied because wrapping mutates it
                spongos
            } else {
                return Ok(Message::orphan(address, preparsed));
            }
        };
        let tagged_packet = tagged_packet::Unwrap::new(&mut linked_msg_spongos);
        let (message, spongos) = preparsed.unwrap(tagged_packet).await?;

        // Store spongos
        self.state.spongos_store.insert(address.relative(), spongos);

        // Store message content into stores

        Ok(Message::from_lets_message(address, message))
    }

    pub async fn backup<P>(&mut self, pwd: P) -> Result<Vec<u8>>
    where
        P: AsRef<[u8]>,
    {
        let mut ctx = sizeof::Context::new();
        ctx.sizeof(&self.state).await?;
        let buf_size = ctx.finalize();

        let mut buf = vec![0; buf_size];

        let mut ctx = wrap::Context::new(&mut buf[..]);
        let key: [u8; 32] = SpongosRng::<KeccakF1600>::new(pwd).gen();
        ctx.absorb(External::new(&NBytes::new(key)))?;
        ctx.wrap(&mut self.state).await?;
        assert!(
            ctx.stream().is_empty(),
            "Missmatch between buffer size expected by SizeOf ({buf_size}) and actual size of Wrap ({})",
            ctx.stream().len()
        );

        Ok(buf)
    }

    pub async fn restore<B, P>(backup: B, pwd: P, transport: T) -> Result<Self>
    where
        P: AsRef<[u8]>,
        B: AsRef<[u8]>,
    {
        let mut ctx = unwrap::Context::new(backup.as_ref());
        let key: [u8; 32] = SpongosRng::<KeccakF1600>::new(pwd).gen();
        ctx.absorb(External::new(&NBytes::new(key)))?;
        let mut state = State::default();
        ctx.unwrap(&mut state).await?;
        Ok(User { transport, state })
    }
}

impl<T> User<T>
where
    T: for<'a> Transport<'a, Msg = TransportMessage>,
{
    pub async fn receive_message(&mut self, address: Address) -> Result<Message>
    where
        T: for<'a> Transport<'a, Msg = TransportMessage>,
    {
        let msg = self.transport.recv_message(address).await?;
        self.handle_message(address, msg).await
    }

    /// Start a [`Messages`] stream to traverse the channel messages
    ///
    /// See the documentation in [`Messages`] for more details and examples.
    pub fn messages(&mut self) -> Messages<T> {
        Messages::new(self)
    }

    /// Iteratively fetches all the next messages until internal state has caught up
    ///
    /// If succeeded, returns the number of messages advanced.
    pub async fn sync(&mut self) -> Result<usize> {
        // ignoring the result is sound as Drain::Error is Infallible
        self.messages().try_fold(0, |n, _| future::ok(n + 1)).await
    }

    /// Iteratively fetches all the pending messages from the transport
    ///
    /// Return a vector with all the messages collected. This is a convenience
    /// method around the [`Messages`] stream. Check out its docs for more
    /// advanced usages.
    pub async fn fetch_next_messages(&mut self) -> Result<Vec<Message>> {
        self.messages().try_collect().await
    }
}

impl<T, TSR> User<T>
where
    T: for<'a> Transport<'a, Msg = TransportMessage, SendResponse = TSR>,
{
    /// Prepare Announcement message.
    pub async fn create_stream(&mut self, stream_idx: usize) -> Result<SendResponse<TSR>> {
        // Check conditions
        if let Some(appaddr) = self.stream_address() {
            bail!(
                "Cannot create a channel, user is already registered to channel {}",
                appaddr
            );
        }
        let user_id = self.identity()?;

        // Generate stream address
        let stream_base_address = AppAddr::gen(self.identifier()?, stream_idx);
        let stream_rel_address = MsgId::gen(stream_base_address, self.identifier()?, INIT_MESSAGE_NUM);
        let stream_address = Address::new(stream_base_address, stream_rel_address);

        // Prepare HDF and PCF
        let header = HDF::new(message_types::ANNOUNCEMENT, ANN_MESSAGE_NUM, self.identifier()?)?;
        let content = PCF::new_final_frame().with_content(announcement::Wrap::new(user_id));

        // Wrap message
        let (transport_msg, spongos) = LetsMessage::new(header, content).wrap().await?;

        // Attempt to send message
        ensure!(
            self.transport.recv_message(stream_address).await.is_err(),
            anyhow!("stream with address '{}' already exists", stream_address)
        );
        let send_response = self.transport.send_message(stream_address, transport_msg).await?;

        // If message has been sent successfully, commit message to stores
        self.state.stream_address = Some(stream_address);
        self.state.author_identifier = Some(self.identifier()?);
        self.state
            .cursor_store
            .insert_cursor(self.identifier()?, INIT_MESSAGE_NUM);
        self.state.spongos_store.insert(stream_address.relative(), spongos);
        Ok(SendResponse::new(stream_address, send_response))
    }

    /// Prepare Subscribe message.
    pub async fn subscribe(&mut self, link_to: MsgId) -> Result<SendResponse<TSR>> {
        // Check conditions
        let stream_address = self
            .stream_address()
            .ok_or_else(|| anyhow!("before subscribing one must receive the announcement of a stream first"))?;

        let user_id = self.identity()?;
        let rel_address = MsgId::gen(stream_address.base(), self.identifier()?, SUB_MESSAGE_NUM);

        // Prepare HDF and PCF
        // Spongos must be copied because wrapping mutates it
        let mut linked_msg_spongos = self
            .state
            .spongos_store
            .get(&link_to)
            .copied()
            .ok_or_else(|| anyhow!("message '{}' not found in spongos store", link_to))?;
        let unsubscribe_key = StdRng::from_entropy().gen();
        let author_ke_pk = self
            .state
            .author_identifier
            .and_then(|author_id| self.state.exchange_keys.get(&author_id))
            .expect("a user that already have an stream address must know the author identifier");
        let content = PCF::new_final_frame().with_content(subscription::Wrap::new(
            &mut linked_msg_spongos,
            unsubscribe_key,
            user_id,
            author_ke_pk,
        ));
        let header = HDF::new(message_types::SUBSCRIPTION, SUB_MESSAGE_NUM, self.identifier()?)?
            .with_linked_msg_address(link_to);

        // Wrap message
        let (transport_msg, _spongos) = LetsMessage::new(header, content).wrap().await?;

        // Attempt to send message
        let message_address = Address::new(stream_address.base(), rel_address);
        ensure!(
            self.transport.recv_message(message_address).await.is_err(),
            anyhow!("there's already a message with address '{}'", message_address)
        );
        let send_response = self.transport.send_message(message_address, transport_msg).await?;

        // If message has been sent successfully, commit message to stores
        // - Subscription messages are not stored in the cursor store
        // - Subscription messages are never stored in spongos to maintain consistency about the view of the
        // set of messages of the stream between all the subscribers and across stateless recovers
        Ok(SendResponse::new(message_address, send_response))
    }

    pub async fn unsubscribe(&mut self, link_to: MsgId) -> Result<SendResponse<TSR>> {
        // Check conditions
        let stream_address = self.stream_address().ok_or_else(|| {
            anyhow!("before sending a subscription one must receive the announcement of a stream first")
        })?;

        let user_id = self.identity()?;
        // Update own's cursor
        let new_cursor = self.next_cursor()?;
        let rel_address = MsgId::gen(stream_address.base(), self.identifier()?, new_cursor);

        // Prepare HDF and PCF
        // Spongos must be copied because wrapping mutates it
        let mut linked_msg_spongos = self
            .state
            .spongos_store
            .get(&link_to)
            .copied()
            .ok_or_else(|| anyhow!("message '{}' not found in spongos store", link_to))?;
        let content = PCF::new_final_frame().with_content(unsubscription::Wrap::new(&mut linked_msg_spongos, user_id));
        let header =
            HDF::new(message_types::UNSUBSCRIPTION, new_cursor, self.identifier()?)?.with_linked_msg_address(link_to);

        // Wrap message
        let (transport_msg, spongos) = LetsMessage::new(header, content).wrap().await?;

        // Attempt to send message
        let message_address = Address::new(stream_address.base(), rel_address);
        ensure!(
            self.transport.recv_message(message_address).await.is_err(),
            anyhow!("there's already a message with address '{}'", message_address)
        );
        let send_response = self.transport.send_message(message_address, transport_msg).await?;

        // If message has been sent successfully, commit message to stores
        self.state.cursor_store.insert_cursor(self.identifier()?, new_cursor);
        self.state.spongos_store.insert(rel_address, spongos);
        Ok(SendResponse::new(message_address, send_response))
    }

    pub async fn send_keyload<'a, Subscribers, Psks>(
        &mut self,
        link_to: MsgId,
        subscribers: Subscribers,
        psk_ids: Psks,
    ) -> Result<SendResponse<TSR>>
    where
        Subscribers: IntoIterator<Item = Permissioned<Identifier>> + Clone,
        Psks: IntoIterator<Item = PskId>,
    {
        // Check conditions
        let stream_address = self
            .stream_address()
            .ok_or_else(|| anyhow!("before sending a keyload one must create a stream first"))?;

        let user_id = self.identity()?;
        // Update own's cursor
        let new_cursor = self.next_cursor()?;
        let rel_address = MsgId::gen(stream_address.base(), self.identifier()?, new_cursor);

        // Prepare HDF and PCF
        let mut announcement_spongos = self
            .state
            .spongos_store
            .get(&stream_address.relative())
            .copied()
            .expect("a subscriber that has received an stream announcement must keep its spongos in store");

        let mut rng = StdRng::from_entropy();
        let encryption_key = rng.gen();
        let nonce = rng.gen();
        let subscribers_with_keys = subscribers
            .clone()
            .into_iter()
            .map(|subscriber| {
                Ok((
                    subscriber,
                    self.state
                        .exchange_keys
                        .get(subscriber.identifier())
                        .ok_or_else(|| anyhow!("unknown subscriber '{}'", subscriber.identifier()))?,
                ))
            })
            .collect::<Result<Vec<(_, _)>>>()?; // collect to handle possible error
        let psk_ids_with_psks = psk_ids
            .into_iter()
            .map(|pskid| {
                Ok((
                    pskid,
                    self.state
                        .psk_store
                        .get(&pskid)
                        .ok_or_else(|| anyhow!("unkown psk '{:?}'", pskid))?,
                ))
            })
            .collect::<Result<Vec<(_, _)>>>()?; // collect to handle possible error
        let content = PCF::new_final_frame().with_content(keyload::Wrap::new(
            &mut announcement_spongos,
            &subscribers_with_keys,
            &psk_ids_with_psks,
            encryption_key,
            nonce,
            user_id,
        ));
        let header = HDF::new(message_types::KEYLOAD, new_cursor, self.identifier()?)?.with_linked_msg_address(link_to);

        // Wrap message
        let (transport_msg, spongos) = LetsMessage::new(header, content).wrap().await?;

        // Attempt to send message
        let message_address = Address::new(stream_address.base(), rel_address);
        ensure!(
            self.transport.recv_message(message_address).await.is_err(),
            anyhow!("there's already a message with address '{}'", message_address)
        );
        let send_response = self.transport.send_message(message_address, transport_msg).await?;

        // If message has been sent successfully, commit message to stores
        for subscriber in subscribers {
            if self.should_store_cursor(&subscriber) {
                self.state
                    .cursor_store
                    .insert_cursor(*subscriber.identifier(), INIT_MESSAGE_NUM);
            }
        }
        self.state.cursor_store.insert_cursor(self.identifier()?, new_cursor);
        self.state.spongos_store.insert(rel_address, spongos);
        Ok(SendResponse::new(message_address, send_response))
    }

    pub async fn send_keyload_for_all(&mut self, link_to: MsgId) -> Result<SendResponse<TSR>> {
        let psks: Vec<PskId> = self.state.psk_store.keys().copied().collect();
        let subscribers: Vec<Permissioned<Identifier>> = self.subscribers().map(Permissioned::Read).collect();
        self.send_keyload(
            link_to,
            // Alas, must collect to release the &self immutable borrow
            subscribers,
            psks,
        )
        .await
    }

    pub async fn send_keyload_for_all_rw(&mut self, link_to: MsgId) -> Result<SendResponse<TSR>> {
        let psks: Vec<PskId> = self.state.psk_store.keys().copied().collect();
        let subscribers: Vec<Permissioned<Identifier>> = self
            .subscribers()
            .map(|s| Permissioned::ReadWrite(s, PermissionDuration::Perpetual))
            .collect();
        self.send_keyload(
            link_to,
            // Alas, must collect to release the &self immutable borrow
            subscribers,
            psks,
        )
        .await
    }

    pub async fn send_signed_packet<P, M>(
        &mut self,
        link_to: MsgId,
        public_payload: P,
        masked_payload: M,
    ) -> Result<SendResponse<TSR>>
    where
        M: AsRef<[u8]>,
        P: AsRef<[u8]>,
    {
        // Check conditions
        let stream_address = self.stream_address().ok_or_else(|| {
            anyhow!("before sending a signed packet one must receive the announcement of a stream first")
        })?;

        // Update own's cursor
        let new_cursor = self.next_cursor()?;
        let rel_address = MsgId::gen(stream_address.base(), self.identifier()?, new_cursor);

        // Prepare HDF and PCF
        // Spongos must be copied because wrapping mutates it
        let mut linked_msg_spongos = self
            .state
            .spongos_store
            .get(&link_to)
            .copied()
            .ok_or_else(|| anyhow!("message '{}' not found in spongos store", link_to))?;
        let content = PCF::new_final_frame().with_content(signed_packet::Wrap::new(
            &mut linked_msg_spongos,
            self.identity()?,
            public_payload.as_ref(),
            masked_payload.as_ref(),
        ));
        let header =
            HDF::new(message_types::SIGNED_PACKET, new_cursor, self.identifier()?)?.with_linked_msg_address(link_to);

        // Wrap message
        let (transport_msg, spongos) = LetsMessage::new(header, content).wrap().await?;

        // Attempt to send message
        let message_address = Address::new(stream_address.base(), rel_address);
        ensure!(
            self.transport.recv_message(message_address).await.is_err(),
            anyhow!("there's already a message with address '{}'", message_address)
        );
        let send_response = self.transport.send_message(message_address, transport_msg).await?;

        // If message has been sent successfully, commit message to stores
        self.state.cursor_store.insert_cursor(self.identifier()?, new_cursor);
        self.state.spongos_store.insert(rel_address, spongos);
        Ok(SendResponse::new(message_address, send_response))
    }

    pub async fn send_tagged_packet<P, M>(
        &mut self,
        link_to: MsgId,
        public_payload: P,
        masked_payload: M,
    ) -> Result<SendResponse<TSR>>
    where
        M: AsRef<[u8]>,
        P: AsRef<[u8]>,
    {
        // Check conditions
        let stream_address = self.stream_address().ok_or_else(|| {
            anyhow!("before sending a tagged packet one must receive the announcement of a stream first")
        })?;

        // Update own's cursor
        let new_cursor = self.next_cursor()?;
        let rel_address = MsgId::gen(stream_address.base(), self.identifier()?, new_cursor);

        // Prepare HDF and PCF
        // Spongos must be copied because wrapping mutates it
        let mut linked_msg_spongos = self
            .state
            .spongos_store
            .get(&link_to)
            .copied()
            .ok_or_else(|| anyhow!("message '{}' not found in spongos store", link_to))?;
        let content = PCF::new_final_frame().with_content(tagged_packet::Wrap::new(
            &mut linked_msg_spongos,
            public_payload.as_ref(),
            masked_payload.as_ref(),
        ));
        let header =
            HDF::new(message_types::TAGGED_PACKET, new_cursor, self.identifier()?)?.with_linked_msg_address(link_to);

        // Wrap message
        let (transport_msg, spongos) = LetsMessage::new(header, content).wrap().await?;

        // Attempt to send message
        let message_address = Address::new(stream_address.base(), rel_address);
        ensure!(
            self.transport.recv_message(message_address).await.is_err(),
            anyhow!("there's already a message with address '{}'", message_address)
        );
        let send_response = self.transport.send_message(message_address, transport_msg).await?;

        // If message has been sent successfully, commit message to stores
        self.state.cursor_store.insert_cursor(self.identifier()?, new_cursor);
        self.state.spongos_store.insert(rel_address, spongos);
        Ok(SendResponse::new(message_address, send_response))
    }
}

#[async_trait(?Send)]
impl ContentSizeof<State> for sizeof::Context {
    async fn sizeof(&mut self, user_state: &State) -> Result<&mut Self> {
        self.mask(Maybe::new(user_state.user_id.as_ref()))?
            .mask(Maybe::new(user_state.stream_address.as_ref()))?
            .mask(Maybe::new(user_state.author_identifier.as_ref()))?;

        let amount_spongos = user_state.spongos_store.len();
        self.mask(Size::new(amount_spongos))?;
        for (address, spongos) in &user_state.spongos_store {
            self.mask(address)?.mask(spongos)?;
        }

        let cursors = user_state.cursor_store.cursors();
        let amount_cursors = cursors.len();
        self.mask(Size::new(amount_cursors))?;
        for (subscriber, cursor) in cursors {
            self.mask(&subscriber)?.mask(Size::new(cursor))?;
        }

        let keys = &user_state.exchange_keys;
        let amount_keys = keys.len();
        self.mask(Size::new(amount_keys))?;
        for (subscriber, ke_pk) in keys {
            self.mask(subscriber)?.mask(ke_pk)?;
        }

        let psks = user_state.psk_store.iter();
        let amount_psks = psks.len();
        self.mask(Size::new(amount_psks))?;
        for (pskid, psk) in psks {
            self.mask(pskid)?.mask(psk)?;
        }
        self.commit()?.squeeze(Mac::new(32))?;
        Ok(self)
    }
}

#[async_trait(?Send)]
impl<'a> ContentWrap<State> for wrap::Context<&'a mut [u8]> {
    async fn wrap(&mut self, user_state: &mut State) -> Result<&mut Self> {
        self.mask(Maybe::new(user_state.user_id.as_ref()))?
            .mask(Maybe::new(user_state.stream_address.as_ref()))?
            .mask(Maybe::new(user_state.author_identifier.as_ref()))?;

        let amount_spongos = user_state.spongos_store.len();
        self.mask(Size::new(amount_spongos))?;
        for (address, spongos) in &user_state.spongos_store {
            self.mask(address)?.mask(spongos)?;
        }

        let cursors = user_state.cursor_store.cursors();
        let amount_cursors = cursors.len();
        self.mask(Size::new(amount_cursors))?;
        for (subscriber, cursor) in cursors {
            self.mask(&subscriber)?.mask(Size::new(cursor))?;
        }

        let keys = &user_state.exchange_keys;
        let amount_keys = keys.len();
        self.mask(Size::new(amount_keys))?;
        for (subscriber, ke_pk) in keys {
            self.mask(subscriber)?.mask(ke_pk)?;
        }

        let psks = user_state.psk_store.iter();
        let amount_psks = psks.len();
        self.mask(Size::new(amount_psks))?;
        for (pskid, psk) in psks {
            self.mask(pskid)?.mask(psk)?;
        }
        self.commit()?.squeeze(Mac::new(32))?;
        Ok(self)
    }
}

#[async_trait(?Send)]
impl<'a> ContentUnwrap<State> for unwrap::Context<&'a [u8]> {
    async fn unwrap(&mut self, user_state: &mut State) -> Result<&mut Self> {
        self.mask(Maybe::new(&mut user_state.user_id))?
            .mask(Maybe::new(&mut user_state.stream_address))?
            .mask(Maybe::new(&mut user_state.author_identifier))?;

        let mut amount_spongos = Size::default();
        self.mask(&mut amount_spongos)?;
        for _ in 0..amount_spongos.inner() {
            let mut address = MsgId::default();
            let mut spongos = Spongos::default();
            self.mask(&mut address)?.mask(&mut spongos)?;
            user_state.spongos_store.insert(address, spongos);
        }

        let mut amount_cursors = Size::default();
        self.mask(&mut amount_cursors)?;
        for _ in 0..amount_cursors.inner() {
            let mut subscriber = Identifier::default();
            let mut cursor = Size::default();
            self.mask(&mut subscriber)?.mask(&mut cursor)?;
            user_state.cursor_store.insert_cursor(subscriber, cursor.inner());
        }

        let mut amount_keys = Size::default();
        self.mask(&mut amount_keys)?;
        for _ in 0..amount_keys.inner() {
            let mut subscriber = Identifier::default();
            let mut key = x25519::PublicKey::from_bytes([0; x25519::PUBLIC_KEY_LENGTH]);
            self.mask(&mut subscriber)?.mask(&mut key)?;
            user_state.exchange_keys.insert(subscriber, key);
        }

        let mut amount_psks = Size::default();
        self.mask(&mut amount_psks)?;
        for _ in 0..amount_psks.inner() {
            let mut pskid = PskId::default();
            let mut psk = Psk::default();
            self.mask(&mut pskid)?.mask(&mut psk)?;
            user_state.psk_store.insert(pskid, psk);
        }

        self.commit()?.squeeze(Mac::new(32))?;
        Ok(self)
    }
}

impl<T> Debug for User<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "\n* identifier: <{}>\n{:?}\n* PSKs: \n{}\n* messages:\n{}\n",
            match self.identifier() {
                Ok(id) => id.to_string(),
                Err(_) => "User has no Identifier".to_string(),
            },
            self.state.cursor_store,
            self.state
                .psk_store
                .keys()
                .map(|pskid| format!("\t<{:?}>\n", pskid))
                .collect::<String>(),
            self.state
                .spongos_store
                .keys()
                .map(|key| format!("\t<{}>\n", key))
                .collect::<String>()
        )
    }
}

/// An streams user equality is determined by the equality of its state. The major consequence of
/// this fact is that two users with the same identity but different transport configurations are
/// considered equal
impl<T> PartialEq for User<T> {
    fn eq(&self, other: &Self) -> bool {
        self.state == other.state
    }
}

/// An streams user equality is determined by the equality of its state. The major consequence of
/// this fact is that two users with the same identity but different transport configurations are
/// considered equal
impl<T> Eq for User<T> {}