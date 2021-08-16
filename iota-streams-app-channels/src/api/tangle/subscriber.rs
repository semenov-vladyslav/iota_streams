//! Customize Subscriber with default parameters for use over the Tangle.

use core::fmt;
use iota_streams_core::{
    err,
    Result,
};

use super::*;
use crate::api::tangle::{
    ChannelType::SingleBranch,
    UnwrappedMessage,
    User,
};

use iota_streams_app::identifier::Identifier;
use iota_streams_core::{
    prelude::{
        String,
        Vec,
    },
    psk::{
        Psk,
        PskId,
    },
    Errors::SingleDepthOperationFailure,
};
use iota_streams_core_edsig::signature::ed25519;

/// Subscriber Object. Contains User API.
pub struct Subscriber<T> {
    user: User<T>,
}

impl<Trans> Subscriber<Trans> {
    /// Create a new Subscriber instance, generate new Ed25519 key pair.
    ///
    /// # Arguments
    /// * `seed` - A string slice representing the seed of the user [Characters: A-Z, 9]
    /// * `transport` - Transport object used for sending and receiving
    pub fn new(seed: &str, transport: Trans) -> Self {
        let user = User::new(seed, SingleBranch, transport);
        Self { user }
    }

    /// Returns a clone of the transport object
    pub fn get_transport(&self) -> &Trans {
        self.user.get_transport()
    }

    /// Returns a boolean representing whether an Announcement message has been processed
    pub fn is_registered(&self) -> bool {
        self.user.is_registered()
    }

    /// Clears inner state except for own keys and link store.
    pub fn unregister(&mut self) {
        self.user.unregister()
    }

    /// Fetch the user ed25519 public key
    pub fn get_public_key(&self) -> &ed25519::PublicKey {
        self.user.get_public_key()
    }

    /// Channel Author's signature public key
    pub fn author_public_key(&self) -> Option<&ed25519::PublicKey> {
        self.user.author_public_key()
    }

    /// Store a PSK in the user instance
    ///
    ///   # Arguments
    ///   * `pskid` - An identifier representing a pre shared key
    ///   * `psk` - A pre shared key
    pub fn store_psk(&mut self, pskid: PskId, psk: Psk) -> Result<()> {
        self.user.store_psk(pskid, psk, true)
    }

    /// Fetch the Address (application instance) of the channel.
    pub fn channel_address(&self) -> Option<&ChannelAddress> {
        self.user.channel_address()
    }

    /// Return boolean representing the sequencing nature of the channel
    pub fn is_multi_branching(&self) -> bool {
        self.user.is_multi_branching()
    }

    /// Return boolean representing whether the implementation type is single depth
    pub fn is_single_depth(&self) -> bool {
        self.user.is_single_depth()
    }

    /// Stores the provided link to the internal sequencing state for the provided participant
    /// [Used for multi-branching sequence state updates]
    ///
    ///   # Arguments
    ///   * `pk` - ed25519 Public Key of the sender of the message
    ///   * `link` - Address link to be stored in internal sequence state mapping
    pub fn store_state(&mut self, id: Identifier, link: &Address) -> Result<()> {
        // TODO: assert!(link.appinst == self.appinst.unwrap());
        self.user.store_state(id, link)
    }

    /// Stores the provided link and sequence number to the internal sequencing state for all participants
    /// [Used for single-branching sequence state updates]
    ///
    ///   # Arguments
    ///   * `link` - Address link to be stored in internal sequence state mapping
    ///   * `seq_num` - New sequence state to be stored in internal sequence state mapping
    pub fn store_state_for_all(&mut self, link: &Address, seq_num: u32) -> Result<()> {
        // TODO: assert!(link.appinst == self.appinst.unwrap());
        self.user.store_state_for_all(link, seq_num)
    }

    /// Fetches the latest PublicKey -> Cursor state mapping from the implementation, allowing the
    /// user to see the latest messages present from each publisher
    pub fn fetch_state(&self) -> Result<Vec<(String, Cursor<Address>)>> {
        let state_list = self.user.fetch_state()?;
        let mut state = Vec::new();
        for (pk, cursor) in state_list {
            state.push((hex::encode(pk.to_bytes()), cursor))
        }
        Ok(state)
    }

    /// Resets the cursor state storage to allow a Subscriber to retrieve all messages in a channel
    /// from scratch
    pub fn reset_state(&mut self) -> Result<()> {
        self.user.reset_state()
    }

    /// Generate a vector containing the next sequenced message identifier for each publishing
    /// participant in the channel
    ///
    ///   # Arguments
    ///   * `branching` - Boolean representing the sequencing nature of the channel
    pub fn gen_next_msg_ids(&mut self, branching: bool) -> Vec<(Identifier, Cursor<Address>)> {
        self.user.gen_next_msg_ids(branching)
    }

    /// Serialize user state and encrypt it with password.
    ///
    ///   # Arguments
    ///   * `pwd` - Encryption password
    pub fn export(&self, pwd: &str) -> Result<Vec<u8>> {
        self.user.export(1, pwd)
    }

    /// Deserialize user state and decrypt it with password.
    ///
    ///   # Arguments
    ///   * `bytes` - Encrypted serialized user state
    ///   * `pwd` - Encryption password
    ///   * `tsp` - Transport object
    pub fn import(bytes: &[u8], pwd: &str, tsp: Trans) -> Result<Self> {
        User::<Trans>::import(bytes, 1, pwd, tsp).map(|user| Self { user })
    }
}

#[cfg(not(feature = "async"))]
impl<Trans: Transport + Clone> Subscriber<Trans> {
    /// Generates a new Subscriber implementation from input. It then syncs state of the user from
    /// the given announcement message link
    ///
    ///  # Arguements
    /// * `seed` - A string slice representing the seed of the user [Characters: A-Z, 9]
    /// * `announcement` - An existing announcement message link for processing
    /// * `transport` - Transport object used for sending and receiving
    pub fn recover(seed: &str, announcement: &Address, transport: Trans) -> Result<Self> {
        let mut subscriber = Subscriber::new(seed, transport);
        subscriber.receive_announcement(announcement)?;
        subscriber.sync_state();

        Ok(subscriber)
    }

    /// Create and Send a Subscribe message to a Channel app instance.
    ///
    /// # Arguments
    /// * `link_to` - Address of the Channel Announcement message
    pub fn send_subscribe(&mut self, link_to: &Address) -> Result<Address> {
        self.user.send_subscribe(link_to)
    }

    /// Create and send a signed packet.
    ///
    ///  # Arguments
    ///  * `link_to` - Address of the message the keyload will be attached to
    ///  * `public_payload` - Wrapped vector of Bytes to have public access
    ///  * `masked_payload` - Wrapped vector of Bytes to have masked access
    pub fn send_tagged_packet(
        &mut self,
        link_to: &Address,
        public_payload: &Bytes,
        masked_payload: &Bytes,
    ) -> Result<(Address, Option<Address>)> {
        if self.is_single_depth() {
            return err(SingleDepthOperationFailure);
        }
        self.user.send_tagged_packet(link_to, public_payload, masked_payload)
    }

    /// Create and send a tagged packet.
    ///
    ///  # Arguments
    ///  * `link_to` - Address of the message the keyload will be attached to
    ///  * `public_payload` - Wrapped vector of Bytes to have public access
    ///  * `masked_payload` - Wrapped vector of Bytes to have masked access
    pub fn send_signed_packet(
        &mut self,
        link_to: &Address,
        public_payload: &Bytes,
        masked_payload: &Bytes,
    ) -> Result<(Address, Option<Address>)> {
        if self.is_single_depth() {
            return err(SingleDepthOperationFailure);
        }
        self.user.send_signed_packet(link_to, public_payload, masked_payload)
    }

    // Unsubscribe from the Channel app instance.
    // pub pub fn unsubscribe(&mut self, link_to: &Address) -> Result<Message> {
    // TODO: lookup link_to Subscribe message.
    // self.user.unsubscribe(link_to.rel(), MsgInfo::Unsubscribe)
    // }

    /// Receive and Process an announcement message.
    ///
    /// # Arguments
    /// * `link_to` - Address of the Channel Announcement message
    pub fn receive_announcement(&mut self, link: &Address) -> Result<()> {
        self.user.receive_announcement(link)
    }

    /// Receive and process a keyload message.
    ///
    ///  # Arguments
    ///  * `link` - Address of the message to be processed
    pub fn receive_keyload(&mut self, link: &Address) -> Result<bool> {
        self.user.receive_keyload(link)
    }

    /// Receive and process a signed packet message.
    ///
    ///  # Arguments
    ///  * `link` - Address of the message to be processed
    pub fn receive_signed_packet(&mut self, link: &Address) -> Result<(ed25519::PublicKey, Bytes, Bytes)> {
        self.user.receive_signed_packet(link)
    }

    /// Receive and process a tagged packet message.
    ///
    ///  # Arguments
    ///  * `link` - Address of the message to be processed
    pub fn receive_tagged_packet(&mut self, link: &Address) -> Result<(Bytes, Bytes)> {
        self.user.receive_tagged_packet(link)
    }

    /// Receive and process a sequence message.
    ///
    ///  # Arguments
    ///  * `link` - Address of the message to be processed
    pub fn receive_sequence(&mut self, link: &Address) -> Result<Address> {
        self.user.receive_sequence(link)
    }

    /// Retrieves the next message for each user (if present in transport layer) and returns them
    pub fn fetch_next_msgs(&mut self) -> Vec<UnwrappedMessage> {
        self.user.fetch_next_msgs()
    }

    /// Retrieves the previous message from the message specified (provided the user has access to it)
    pub fn fetch_prev_msg(&mut self, link: &Address) -> Result<UnwrappedMessage> {
        self.user.fetch_prev_msg(link)
    }

    /// Retrieves a specified number of previous messages from an original specified messsage link
    pub fn fetch_prev_msgs(&mut self, link: &Address, max: usize) -> Result<Vec<UnwrappedMessage>> {
        self.user.fetch_prev_msgs(link, max)
    }

    /// Iteratively fetches next message until no new messages can be found, and return a vector
    /// containing all of them.
    pub fn fetch_all_next_msgs(&mut self) -> Vec<UnwrappedMessage> {
        let mut exists = true;
        let mut msgs = Vec::new();
        while exists {
            let next_msgs = self.fetch_next_msgs();
            if next_msgs.is_empty() {
                exists = false
            } else {
                msgs.extend(next_msgs)
            }
        }
        msgs
    }

    /// Iteratively fetches next messages until internal state has caught up
    pub fn sync_state(&mut self) {
        let mut exists = true;
        while exists {
            exists = !self.fetch_next_msgs().is_empty()
        }
    }

    /// Receive and process a message of unknown type. Message will be handled appropriately and
    /// the unwrapped contents returned
    ///
    ///   # Arguments
    ///   * `link` - Address of the message to be processed
    ///   * `pk` - Optional ed25519 Public Key of the sending participant. None if unknown
    pub fn receive_msg(&mut self, link: &Address) -> Result<UnwrappedMessage> {
        self.user.receive_message(link)
    }

    pub fn receive_msg_by_sequence(&mut self, anchor_link: &Address, msg_num: u32) -> Result<UnwrappedMessage> {
        self.user.receive_msg_by_sequence(anchor_link, msg_num)
    }
}

#[cfg(feature = "async")]
impl<Trans: Transport + Clone> Subscriber<Trans> {
    /// Generates a new Subscriber implementation from input. It then syncs state of the user from
    /// the given announcement message link
    ///
    ///  # Arguements
    /// * `seed` - A string slice representing the seed of the user [Characters: A-Z, 9]
    /// * `announcement` - An existing announcement message link for processing
    /// * `transport` - Transport object used for sending and receiving
    pub async fn recover(seed: &str, announcement: &Address, transport: Trans) -> Result<Self> {
        let mut subscriber = Subscriber::new(seed, transport);
        subscriber.receive_announcement(announcement).await?;
        subscriber.sync_state().await;

        Ok(subscriber)
    }

    /// Create and Send a Subscribe message to a Channel app instance.
    ///
    /// # Arguments
    /// * `link_to` - Address of the Channel Announcement message
    pub async fn send_subscribe(&mut self, link_to: &Address) -> Result<Address> {
        self.user.send_subscribe(link_to).await
    }

    /// Create and send a signed packet.
    ///
    ///  # Arguments
    ///  * `link_to` - Address of the message the keyload will be attached to
    ///  * `public_payload` - Wrapped vector of Bytes to have public access
    ///  * `masked_payload` - Wrapped vector of Bytes to have masked access
    pub async fn send_tagged_packet(
        &mut self,
        link_to: &Address,
        public_payload: &Bytes,
        masked_payload: &Bytes,
    ) -> Result<(Address, Option<Address>)> {
        if self.is_single_depth() {
            return err(SingleDepthOperationFailure);
        }
        self.user
            .send_tagged_packet(link_to, public_payload, masked_payload)
            .await
    }

    /// Create and send a tagged packet.
    ///
    ///  # Arguments
    ///  * `link_to` - Address of the message the keyload will be attached to
    ///  * `public_payload` - Wrapped vector of Bytes to have public access
    ///  * `masked_payload` - Wrapped vector of Bytes to have masked access
    pub async fn send_signed_packet(
        &mut self,
        link_to: &Address,
        public_payload: &Bytes,
        masked_payload: &Bytes,
    ) -> Result<(Address, Option<Address>)> {
        if self.is_single_depth() {
            return err(SingleDepthOperationFailure);
        }
        self.user
            .send_signed_packet(link_to, public_payload, masked_payload)
            .await
    }

    // Unsubscribe from the Channel app instance.
    // pub pub async fn unsubscribe(&mut self, link_to: &Address) -> Result<Message> {
    // TODO: lookup link_to Subscribe message.
    // self.user.unsubscribe(link_to.rel(), MsgInfo::Unsubscribe).await
    // }

    /// Receive and Process an announcement message.
    ///
    /// # Arguments
    /// * `link` - Address of the Channel Announcement message
    pub async fn receive_announcement(&mut self, link: &Address) -> Result<()> {
        self.user.receive_announcement(link).await
    }

    /// Receive and process a keyload message.
    ///
    ///  # Arguments
    ///  * `link` - Address of the message to be processed
    pub async fn receive_keyload(&mut self, link: &Address) -> Result<bool> {
        self.user.receive_keyload(link).await
    }

    /// Receive and process a signed packet message.
    ///
    ///  # Arguments
    ///  * `link` - Address of the message to be processed
    pub async fn receive_signed_packet(&mut self, link: &Address) -> Result<(ed25519::PublicKey, Bytes, Bytes)> {
        self.user.receive_signed_packet(link).await
    }

    /// Receive and process a tagged packet message.
    ///
    ///  # Arguments
    ///  * `link` - Address of the message to be processed
    pub async fn receive_tagged_packet(&mut self, link: &Address) -> Result<(Bytes, Bytes)> {
        self.user.receive_tagged_packet(link).await
    }

    /// Receive and process a sequence message.
    ///
    ///  # Arguments
    ///  * `link` - Address of the message to be processed
    pub async fn receive_sequence(&mut self, link: &Address) -> Result<Address> {
        self.user.receive_sequence(link).await
    }

    /// Retrieves the next message for each user (if present in transport layer) and returns them
    pub async fn fetch_next_msgs(&mut self) -> Vec<UnwrappedMessage> {
        self.user.fetch_next_msgs().await
    }

    /// Retrieves the previous message from the message specified (provided the user has access to it)
    pub async fn fetch_prev_msg(&mut self, link: &Address) -> Result<UnwrappedMessage> {
        self.user.fetch_prev_msg(link).await
    }

    /// Retrieves a specified number of previous messages from an original specified messsage link
    pub async fn fetch_prev_msgs(&mut self, link: &Address, max: usize) -> Result<Vec<UnwrappedMessage>> {
        self.user.fetch_prev_msgs(link, max).await
    }

    /// Iteratively fetches next message until no new messages can be found, and return a vector
    /// containing all of them.
    pub async fn fetch_all_next_msgs(&mut self) -> Vec<UnwrappedMessage> {
        let mut exists = true;
        let mut msgs = Vec::new();
        while exists {
            let next_msgs = self.fetch_next_msgs().await;
            if next_msgs.is_empty() {
                exists = false
            } else {
                msgs.extend(next_msgs)
            }
        }
        msgs
    }

    /// Iteratively fetches next messages until internal state has caught up
    pub async fn sync_state(&mut self) {
        let mut exists = true;
        while exists {
            exists = !self.fetch_next_msgs().await.is_empty()
        }
    }

    /// Receive and process a message of unknown type. Message will be handled appropriately and
    /// the unwrapped contents returned
    ///
    ///   # Arguments
    ///   * `link` - Address of the message to be processed
    ///   * `pk` - Optional ed25519 Public Key of the sending participant. None if unknown
    pub async fn receive_msg(&mut self, link: &Address) -> Result<UnwrappedMessage> {
        self.user.receive_message(link).await
    }

    pub async fn receive_msg_by_sequence(&mut self, anchor_link: &Address, msg_num: u32) -> Result<UnwrappedMessage> {
        self.user.receive_msg_by_sequence(anchor_link, msg_num).await
    }
}

impl<T: Transport + Clone> fmt::Display for Subscriber<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "<{}>\n{}",
            hex::encode(self.user.user.sig_kp.public.as_bytes()),
            self.user.user.key_store
        )
    }
}
