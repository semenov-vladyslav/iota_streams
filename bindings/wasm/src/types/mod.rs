use core::{
    cell::RefCell,
    str::FromStr,
};
use iota_streams::{
    app::{
        message::Cursor as ApiCursor,
        transport::tangle::client::{
            iota_client::{
                bee_rest_api::types::{
                    dtos::LedgerInclusionStateDto,
                    responses::MessageMetadataResponse as ApiMessageMetadata,
                },
                MilestoneResponse as ApiMilestoneResponse,
            },
            Client,
            Details as ApiDetails,
            SendOptions as ApiSendOptions,
        },
    },
    app_channels::api::tangle::{
        Address as ApiAddress,
        ChannelAddress as ApiChannelAddress,
        ChannelType as ApiChannelType,
        MessageContent,
        MsgId as ApiMsgId,
        PublicKey,
        UnwrappedMessage,
    },
    core::{
        prelude::{
            Rc,
            String,
            ToString,
        },
        psk::{
            pskid_from_hex_str,
            pskid_to_hex_string,
        },
        Error as ApiError,
    },
    ddml::types::hex,
};
use wasm_bindgen::prelude::*;

use iota_streams::{
    app::identifier::Identifier,
    core::psk::PskId,
};
use js_sys::Array;

pub type Result<T> = core::result::Result<T, JsValue>;

/// [`Result`] trait-extension to add convenience methods for error handling
pub(crate) trait ResultExt<T, E> {
    /// Convert the potential error of the [`Result`] into a [`wasm_bindgen::JsValue`]
    /// # Example
    /// ```
    /// # use wasm_bindgen::JsValue;
    ///
    /// #[wasm_bindgen(js_name = "parseInt")]
    /// fn parse_int(string: &str) -> Result<u64, JsValue> {
    ///     string.parse().into_js_err()
    /// }
    /// ```
    fn into_js_result(self) -> core::result::Result<T, JsValue>;
}

impl<T, E> ResultExt<T, E> for core::result::Result<T, E>
where
    E: ToString,
{
    fn into_js_result(self) -> Result<T> {
        self.map_err(|e| JsValue::from_str(&e.to_string()))
    }
}

#[wasm_bindgen]
pub struct SendOptions {
    url: String,
    pub local_pow: bool,
}

impl From<SendOptions> for ApiSendOptions {
    fn from(options: SendOptions) -> Self {
        Self {
            url: options.url,
            local_pow: options.local_pow,
        }
    }
}

#[wasm_bindgen]
impl SendOptions {
    #[wasm_bindgen(constructor)]
    pub fn new(url: String, local_pow: bool) -> Self {
        Self { url, local_pow }
    }

    #[wasm_bindgen(setter)]
    pub fn set_url(&mut self, url: String) {
        self.url = url
    }

    #[wasm_bindgen(getter)]
    pub fn url(&self) -> String {
        self.url.clone()
    }

    #[wasm_bindgen]
    #[allow(clippy::should_implement_trait)]
    pub fn clone(&self) -> Self {
        SendOptions {
            url: self.url.clone(),
            local_pow: self.local_pow,
        }
    }
}

/// Tangle representation of a Message Link.
///
/// An `Address` is comprised of 2 distinct parts: the channel identifier
/// ({@link ChannelAddress}) and the message identifier
/// ({@link MsgId}). The channel identifier is unique per channel and is common in the
/// `Address` of all messages published in it. The message identifier is
/// produced pseudo-randomly out of the the message's sequence number, the
/// previous message identifier, and other internal properties.
#[wasm_bindgen]
#[derive(Clone, Copy)]
pub struct Address(ApiAddress);

#[wasm_bindgen]
impl Address {
    #[wasm_bindgen(constructor)]
    pub fn new(channel_address: ChannelAddress, msgid: MsgId) -> Self {
        Address(ApiAddress::new(channel_address.into_inner(), msgid.into_inner()))
    }

    #[wasm_bindgen(getter, js_name = "channelAddress")]
    pub fn channel_address(&self) -> ChannelAddress {
        ChannelAddress(self.0.appinst)
    }

    #[wasm_bindgen(getter, js_name = "msgId")]
    pub fn msg_id(&self) -> MsgId {
        MsgId(self.0.msgid)
    }

    /// Generate the hash used to index the {@link Message} published in this address.
    ///
    /// Currently this hash is computed with {@link https://en.wikipedia.org/wiki/BLAKE_(hash_function)#BLAKE2|Blake2b256}.
    /// The returned Uint8Array contains the binary digest of the hash. To obtain the hexadecimal representation of the
    /// hash, use the convenience method {@link Address#toMsgIndexHex}.
    #[wasm_bindgen(js_name = "toMsgIndex")]
    pub fn to_msg_index(&self) -> Box<[u8]> {
        self.0.to_msg_index().as_slice().into()
    }

    /// Generate the hash used to index the {@link Message} published in this address.
    ///
    /// Currently this hash is computed with {@link https://en.wikipedia.org/wiki/BLAKE_(hash_function)#BLAKE2|Blake2b256}.
    /// The returned String contains the hexadecimal digest of the hash. To obtain the binary digest of the hash,
    /// use the method {@link Address#toMsgIndex}.
    #[wasm_bindgen(js_name = "toMsgIndexHex")]
    pub fn to_msg_index_hex(&self) -> String {
        format!("{:x}", self.0.to_msg_index())
    }

    /// Render the `Address` as a colon-separated String of the hex-encoded {@link Address#channelAddress} and
    /// {@link Address#msgId} (`<channelAddressHex>:<msgIdHex>`) suitable for exchanging the `Address` between
    /// participants. To convert the String back to an `Address`, use {@link Address.parse}.
    ///
    /// @see Address.parse
    #[allow(clippy::inherent_to_string)]
    #[wasm_bindgen(js_name = "toString")]
    pub fn to_string(&self) -> String {
        self.0.to_string()
    }

    /// Decode an `Address` out of a String. The String must follow the format used by {@link Address#toString}
    ///
    /// @throws Throws an error if String does not follow the format `<channelAddressHex>:<msgIdHex>`
    ///
    /// @see Address#toString
    /// @see ChannelAddress#hex
    /// @see MsgId#hex
    pub fn parse(string: &str) -> Result<Address> {
        Ok(Self(string.parse().into_js_result()?))
    }

    pub fn copy(&self) -> Self {
        *self
    }
}

impl Address {
    // non-JS methods

    pub fn as_inner(&self) -> &ApiAddress {
        &self.0
    }
}

impl From<ApiAddress> for Address {
    fn from(address: ApiAddress) -> Self {
        Self(address)
    }
}

impl AsRef<ApiAddress> for Address {
    fn as_ref(&self) -> &ApiAddress {
        self.as_inner()
    }
}

impl FromStr for Address {
    type Err = ApiError;
    fn from_str(string: &str) -> core::result::Result<Self, Self::Err> {
        Ok(Self(string.parse()?))
    }
}

pub type ClientWrap = Rc<RefCell<Client>>;

/// Channel application instance identifier (40 Byte)
#[wasm_bindgen]
#[derive(Clone, Copy)]
pub struct ChannelAddress(ApiChannelAddress);

#[wasm_bindgen]
impl ChannelAddress {
    /// Render the `ChannelAddress` as a 40 Byte {@link https://developer.mozilla.org/es/docs/Web/JavaScript/Reference/Global_Objects/Uint8Array|Uint8Array}
    ///
    /// @see ChannelAddress#hex
    pub fn bytes(&self) -> Box<[u8]> {
        self.0.as_bytes().into()
    }

    /// Render the `ChannelAddress` as a 40 Byte (80 char) hexadecimal String
    ///
    /// @see ChannelAddress#bytes
    pub fn hex(&self) -> String {
        self.0.to_hex_string()
    }

    /// Render the `ChannelAddress` as an exchangeable String. Currently
    /// outputs the same as {@link ChannelAddress#hex}.
    ///
    /// @see ChannelAddress#hex
    /// @see ChannelAddress.parse
    #[allow(clippy::inherent_to_string)]
    #[wasm_bindgen(js_name = "toString")]
    pub fn to_string(&self) -> String {
        self.0.to_string()
    }

    /// Decode a `ChannelAddress` out of a String. The string must be a 80 char long hexadecimal string.
    ///
    /// @see ChannelAddress#toString
    /// @throws Throws error if string does not follow the expected format
    pub fn parse(string: &str) -> Result<ChannelAddress> {
        Ok(Self(string.parse().into_js_result()?))
    }

    pub fn copy(&self) -> Self {
        *self
    }

    fn into_inner(self) -> ApiChannelAddress {
        self.0
    }
}

/// Message identifier (12 Byte). Unique within a Channel.
#[wasm_bindgen]
#[derive(Clone, Copy)]
pub struct MsgId(ApiMsgId);

#[wasm_bindgen]
impl MsgId {
    /// Render the `MsgId` as a 12 Byte {@link https://developer.mozilla.org/es/docs/Web/JavaScript/Reference/Global_Objects/Uint8Array|Uint8Array}
    ///
    /// @see MsgId#hex
    pub fn bytes(&self) -> Box<[u8]> {
        self.0.as_bytes().into()
    }

    /// Render the `MsgId` as a 12 Byte (24 char) hexadecimal String
    ///
    /// @see MsgId#bytes
    pub fn hex(&self) -> String {
        self.0.to_hex_string()
    }

    /// Render the `MsgId` as an exchangeable String. Currently
    /// outputs the same as {@link MsgId#hex}.
    ///
    /// @see MsgId#hex
    /// @see MsgId.parse
    #[allow(clippy::inherent_to_string)]
    #[wasm_bindgen(js_name = "toString")]
    pub fn to_string(&self) -> String {
        self.0.to_string()
    }

    /// Decode a `MsgId` out of a String. The string must be a 24 char long hexadecimal string.
    ///
    /// @see Msgid#toString
    /// @throws Throws error if string does not follow the expected format
    pub fn parse(string: &str) -> Result<MsgId> {
        Ok(Self(string.parse().into_js_result()?))
    }

    pub fn copy(&self) -> Self {
        *self
    }

    fn into_inner(self) -> ApiMsgId {
        self.0
    }
}

pub fn get_message_contents(msgs: Vec<UnwrappedMessage>) -> Vec<UserResponse> {
    let mut payloads = Vec::new();
    for msg in msgs {
        match msg.body {
            MessageContent::SignedPacket {
                pk,
                public_payload: p,
                masked_payload: m,
            } => payloads.push(UserResponse::new(
                msg.link.into(),
                None,
                Some(Message::new(Some(hex::encode(pk.to_bytes())), p.0, m.0)),
            )),
            MessageContent::TaggedPacket {
                public_payload: p,
                masked_payload: m,
            } => payloads.push(UserResponse::new(
                msg.link.into(),
                None,
                Some(Message::new(None, p.0, m.0)),
            )),
            MessageContent::Sequence => (),
            _ => payloads.push(UserResponse::new(msg.link.into(), None, None)),
        };
    }
    payloads
}

#[wasm_bindgen]
pub enum ChannelType {
    SingleBranch,
    MultiBranch,
    SingleDepth,
}

impl From<ChannelType> for ApiChannelType {
    fn from(channel_type: ChannelType) -> Self {
        match channel_type {
            ChannelType::SingleBranch => ApiChannelType::SingleBranch,
            ChannelType::MultiBranch => ApiChannelType::MultiBranch,
            ChannelType::SingleDepth => ApiChannelType::SingleDepth,
        }
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct UserResponse {
    link: Address,
    seq_link: Option<Address>,
    message: Option<Message>,
}

#[wasm_bindgen]
pub struct NextMsgId {
    identifier: String,
    msgid: Address,
}

#[wasm_bindgen]
pub struct UserState {
    identifier: String,
    cursor: Cursor,
}

#[wasm_bindgen]
pub struct Cursor {
    link: Address,
    seq_no: u32,
    branch_no: u32,
}

impl From<ApiCursor<ApiAddress>> for Cursor {
    fn from(cursor: ApiCursor<ApiAddress>) -> Self {
        Cursor {
            link: cursor.link.into(),
            seq_no: cursor.seq_no,
            branch_no: cursor.branch_no,
        }
    }
}

#[wasm_bindgen]
impl UserState {
    pub fn new(identifier: String, cursor: Cursor) -> Self {
        UserState { identifier, cursor }
    }

    #[wasm_bindgen(getter)]
    pub fn identifier(&self) -> String {
        self.identifier.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn link(&self) -> Address {
        self.cursor.link
    }

    #[wasm_bindgen(getter, js_name = "seqNo")]
    pub fn seq_no(&self) -> u32 {
        self.cursor.seq_no
    }

    #[wasm_bindgen(getter, js_name = "branchNo")]
    pub fn branch_no(&self) -> u32 {
        self.cursor.branch_no
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct Message {
    identifier: Option<String>,
    public_payload: Vec<u8>,
    masked_payload: Vec<u8>,
}

#[wasm_bindgen]
#[derive(Default)]
pub struct PskIds {
    pub(crate) ids: Vec<PskId>,
}

#[wasm_bindgen]
impl PskIds {
    pub fn new() -> Self {
        Self { ids: Vec::new() }
    }

    pub fn add(&mut self, id: String) -> Result<()> {
        let pskid = pskid_from_hex_str(&id).into_js_result()?;
        self.ids.push(pskid);
        Ok(())
    }

    pub fn get_ids(&self) -> Array {
        self.ids
            .iter()
            .map(|pskid| JsValue::from(pskid_to_hex_string(pskid)))
            .collect()
    }
}

#[wasm_bindgen]
pub struct PublicKeys {
    pub(crate) pks: Vec<PublicKey>,
}

pub(crate) fn identifier_to_string(id: &Identifier) -> String {
    hex::encode(&id.to_bytes())
}

pub(crate) fn public_key_to_string(pk: &PublicKey) -> String {
    hex::encode(pk.as_bytes())
}

pub(crate) fn public_key_from_string(hex_str: &str) -> Result<PublicKey> {
    let bytes = hex::decode(hex_str).into_js_result()?;
    PublicKey::from_bytes(&bytes).into_js_result()
}

#[wasm_bindgen]
impl PublicKeys {
    pub fn new() -> Self {
        Self { pks: Vec::new() }
    }

    pub fn add(&mut self, id: String) -> Result<()> {
        self.pks.push(public_key_from_string(&id)?);
        Ok(())
    }

    pub fn get_pks(&self) -> Array {
        self.pks
            .iter()
            .map(|pk| JsValue::from(public_key_to_string(pk)))
            .collect()
    }
}

#[wasm_bindgen]
impl Message {
    pub fn default() -> Message {
        Self::new(None, Vec::new(), Vec::new())
    }

    pub fn new(identifier: Option<String>, public_payload: Vec<u8>, masked_payload: Vec<u8>) -> Message {
        Message {
            identifier,
            public_payload,
            masked_payload,
        }
    }

    pub fn get_identifier(&self) -> String {
        self.identifier.clone().unwrap_or_default()
    }

    pub fn get_public_payload(&self) -> Array {
        self.public_payload.clone().into_iter().map(JsValue::from).collect()
    }

    pub fn get_masked_payload(&self) -> Array {
        self.masked_payload.clone().into_iter().map(JsValue::from).collect()
    }
}

#[wasm_bindgen]
impl NextMsgId {
    pub fn new(identifier: String, msgid: Address) -> Self {
        NextMsgId { identifier, msgid }
    }

    #[wasm_bindgen(getter)]
    pub fn identifier(&self) -> String {
        self.identifier.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn link(&self) -> Address {
        self.msgid
    }
}

#[wasm_bindgen]
impl UserResponse {
    pub fn new(link: Address, seq_link: Option<Address>, message: Option<Message>) -> Self {
        UserResponse {
            link,
            seq_link,
            message,
        }
    }

    #[wasm_bindgen(js_name = "fromStrings")]
    pub fn from_strings(link: String, seq_link: Option<String>, message: Option<Message>) -> Result<UserResponse> {
        Ok(UserResponse {
            link: Address::from_str(&link).into_js_result()?,
            seq_link: seq_link
                .as_deref()
                .map(Address::from_str)
                .transpose()
                .into_js_result()?,
            message,
        })
    }

    pub fn copy(&self) -> Self {
        self.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn link(&self) -> Address {
        self.link
    }

    #[wasm_bindgen(getter, js_name = "seqLink")]
    pub fn seq_link(&self) -> Option<Address> {
        self.seq_link
    }

    #[wasm_bindgen(getter)]
    pub fn message(&mut self) -> Option<Message> {
        self.message.clone()
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct Details {
    metadata: MessageMetadata,
    milestone: Option<MilestoneResponse>,
}

#[wasm_bindgen]
impl Details {
    pub fn get_metadata(&self) -> MessageMetadata {
        self.metadata.clone()
    }

    pub fn get_milestone(&self) -> Option<MilestoneResponse> {
        self.milestone.clone()
    }
}

impl From<ApiDetails> for Details {
    fn from(details: ApiDetails) -> Self {
        Self {
            metadata: details.metadata.into(),
            milestone: match details.milestone {
                Some(ms) => Some(ms.into()),
                None => None,
            },
        }
    }
}

#[wasm_bindgen]
#[derive(Copy, Clone)]
pub enum LedgerInclusionState {
    Conflicting = 0,
    Included = 1,
    NoTransaction = 2,
}

impl From<LedgerInclusionStateDto> for LedgerInclusionState {
    fn from(state: LedgerInclusionStateDto) -> Self {
        match state {
            LedgerInclusionStateDto::Conflicting => LedgerInclusionState::Conflicting,
            LedgerInclusionStateDto::Included => LedgerInclusionState::Included,
            LedgerInclusionStateDto::NoTransaction => LedgerInclusionState::NoTransaction,
        }
    }
}

#[wasm_bindgen]
pub struct MessageMetadata {
    message_id: String,
    parent_message_ids: Vec<String>,

    pub is_solid: bool,
    pub referenced_by_milestone_index: Option<u32>,
    pub milestone_index: Option<u32>,
    pub ledger_inclusion_state: Option<LedgerInclusionState>,
    pub conflict_reason: Option<u8>,
    pub should_promote: Option<bool>,
    pub should_reattach: Option<bool>,
}

#[wasm_bindgen]
impl MessageMetadata {
    #[wasm_bindgen(getter)]
    pub fn message_id(&self) -> String {
        self.message_id.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn get_parent_message_ids(&self) -> Array {
        self.parent_message_ids.iter().map(JsValue::from).collect()
    }
}

impl Clone for MessageMetadata {
    fn clone(&self) -> MessageMetadata {
        MessageMetadata {
            message_id: self.message_id.clone(),
            parent_message_ids: self.parent_message_ids.clone(),
            is_solid: self.is_solid,
            referenced_by_milestone_index: self.referenced_by_milestone_index,
            milestone_index: self.milestone_index,
            ledger_inclusion_state: self.ledger_inclusion_state,
            conflict_reason: self.conflict_reason,
            should_promote: self.should_promote,
            should_reattach: self.should_reattach,
        }
    }
}

impl From<ApiMessageMetadata> for MessageMetadata {
    fn from(metadata: ApiMessageMetadata) -> Self {
        Self {
            message_id: metadata.message_id,
            parent_message_ids: metadata.parent_message_ids.clone(),
            is_solid: metadata.is_solid,
            referenced_by_milestone_index: metadata.referenced_by_milestone_index,
            milestone_index: metadata.milestone_index,
            ledger_inclusion_state: match metadata.ledger_inclusion_state {
                None => None,
                Some(inc) => Some(inc.into()),
            },
            conflict_reason: metadata.conflict_reason,
            should_promote: metadata.should_promote,
            should_reattach: metadata.should_reattach,
        }
    }
}

#[wasm_bindgen]
pub struct MilestoneResponse {
    /// Milestone index.
    pub index: u32,
    /// Milestone message id.
    message_id: String,
    /// Milestone timestamp.
    pub timestamp: u64,
}

#[wasm_bindgen]
impl MilestoneResponse {
    #[wasm_bindgen(getter)]
    pub fn message_id(&self) -> String {
        self.message_id.clone()
    }
}

impl Clone for MilestoneResponse {
    fn clone(&self) -> MilestoneResponse {
        MilestoneResponse {
            index: self.index,
            message_id: self.message_id.clone(),
            timestamp: self.timestamp,
        }
    }
}

impl From<ApiMilestoneResponse> for MilestoneResponse {
    fn from(milestone: ApiMilestoneResponse) -> Self {
        Self {
            index: milestone.index,
            message_id: milestone.message_id.to_string(),
            timestamp: milestone.timestamp,
        }
    }
}
