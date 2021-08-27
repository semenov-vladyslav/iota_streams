//! Default parameters for Author and Subscriber types.

use super::key_store::KeyMap;
use iota_streams_app::{
    message::{
        self,
        BinaryBody,
    },
    transport::{
        self,
        tangle::{
            AppInst,
            DefaultTangleLinkGenerator,
            MsgId,
            TangleAddress,
            TangleMessage,
        },
    },
};

#[cfg(any(feature = "sync-client", feature = "async-client", feature = "wasm-client"))]
use iota_streams_app::transport::tangle::client::Details as ClientDetails;

pub use message::Cursor;
// Bring trait methods into scope publicly.
pub use message::LinkGenerator;
pub use transport::{
    Transport as _,
    TransportOptions,
};

pub use super::ChannelType;
use super::DefaultF;
use iota_streams_core::psk;
use iota_streams_ddml::link_store::DefaultLinkStore;
pub use iota_streams_ddml::types::Bytes;

use iota_streams_core::signature::ed25519;

/// Identifiers for Pre-Shared Keys
pub type PskIds = psk::PskIds;

/// Tangle Address Link type.
pub type Address = TangleAddress;
/// Tangle Address representing Channel Application Instance.
pub type ChannelAddress = AppInst;

/// Binary encoded message type.
pub type Message = TangleMessage<DefaultF>;
// Details for a message on our tangle transport
#[cfg(any(feature = "sync-client", feature = "async-client", feature = "wasm-client"))]
pub type Details = ClientDetails;

/// Wrapped Message for sending and commit
pub type WrappedMessage = message::WrappedMessage<DefaultF, Address>;
/// Wrapped Spongos state with Address identifier
pub type WrapState = message::WrapState<DefaultF, Address>;
/// Wrapper for optional sequence message and state
pub type WrappedSequence = super::user::WrappedSequence<DefaultF, Address>;
/// Wrapped sequencing information with optional WrapState
pub type WrapStateSequence = super::user::WrapStateSequence<DefaultF, Address>;
/// Ed25519 Public Key
pub type PublicKey = ed25519::PublicKey;

/// Message type with parsed header.
pub type Preparsed<'a> = message::PreparsedMessage<'a, DefaultF, Address>;

/// Sequence State information
pub type SeqState = Cursor<MsgId>;
/// Identifier Key Mapping for sequence states
pub type KeyStore = KeyMap<SeqState>;

/// Link Generator specifies algorithm for generating new message addressed.
pub type LinkGen = DefaultTangleLinkGenerator<DefaultF>;

/// Link Store.
pub type LinkStore = DefaultLinkStore<DefaultF, MsgId, MsgInfo>;

/// Test Transport.
pub type BucketTransport = transport::BucketTransport<Address, Message>;

/// Transportation trait for Tangle Client implementation
// TODO: Use trait synonyms `pub Transport = transport::Transport<DefaultF, Address>;`.
pub trait Transport: transport::Transport<Address, Message> + Clone {}
impl<T> Transport for T where T: transport::Transport<Address, Message> + Clone {}

mod msginfo;
pub use msginfo::MsgInfo;

/// Message body returned as part of handle message routine.
#[allow(clippy::large_enum_variant)]
pub enum MessageContent {
    Announce,
    Keyload,
    SignedPacket {
        pk: PublicKey,
        public_payload: Bytes,
        masked_payload: Bytes,
    },
    TaggedPacket {
        public_payload: Bytes,
        masked_payload: Bytes,
    },
    Sequence,
    Subscribe,
    Unsubscribe,
    Unreadable,
}

impl MessageContent {
    pub fn new_announce() -> Self {
        Self::Announce
    }

    pub fn new_keyload() -> Self {
        Self::Keyload
    }

    pub fn new_signed_packet(pk: PublicKey, public_payload: Bytes, masked_payload: Bytes) -> Self {
        Self::SignedPacket {
            pk,
            public_payload,
            masked_payload,
        }
    }

    pub fn new_tagged_packet(public_payload: Bytes, masked_payload: Bytes) -> Self {
        Self::TaggedPacket {
            public_payload,
            masked_payload,
        }
    }

    pub fn unreadable() -> Self {
        Self::Unreadable
    }
}

/// Generic unwrapped message type containing possible message contents
pub type UnwrappedMessage = message::GenericMessage<Address, MessageContent>;

/// Generic binary message type for sequence handling
pub type BinaryMessage = message::GenericMessage<Address, BinaryBody<DefaultF>>;

#[allow(clippy::ptr_arg)]
mod user;
/// User object storing the Auth/Sub implementation as well as the transport instance
pub use user::User;

#[allow(clippy::ptr_arg)]
mod author;
/// Tangle-specific Channel Author type.
pub use author::Author;

mod subscriber;
/// Tangle-specific Channel Subscriber type.
pub use subscriber::Subscriber;

pub mod test;
