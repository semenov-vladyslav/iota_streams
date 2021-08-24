use core::{
    cell::RefCell,
    convert::TryFrom,
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
        ChannelType as ApiChannelType,
        MessageContent,
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
pub fn to_result<T, E: ToString>(r: core::result::Result<T, E>) -> Result<T> {
    r.map_err(|e| JsValue::from_str(&e.to_string()))
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

#[wasm_bindgen]
#[derive(Default, PartialEq)]
pub struct Address {
    addr_id: String,
    msg_id: String,
}

#[wasm_bindgen]
impl Address {
    #[wasm_bindgen(getter)]
    pub fn addr_id(&self) -> String {
        self.addr_id.clone()
    }

    #[wasm_bindgen(setter)]
    pub fn set_addr_id(&mut self, addr_id: String) {
        self.addr_id = addr_id;
    }

    #[wasm_bindgen(getter)]
    pub fn msg_id(&self) -> String {
        self.msg_id.clone()
    }

    #[wasm_bindgen(setter)]
    pub fn set_msg_id(&mut self, msg_id: String) {
        self.msg_id = msg_id;
    }

    #[wasm_bindgen(static_method_of = Address)]
    pub fn from_string(link: String) -> Self {
        let link_vec: Vec<&str> = link
            .strip_prefix("<")
            .unwrap_or(&link)
            .strip_suffix(">")
            .unwrap_or(&link)
            .split(':')
            .collect();

        Address {
            addr_id: link_vec[0].to_string(),
            msg_id: link_vec[1].to_string(),
        }
    }

    #[wasm_bindgen]
    pub fn to_string(&self) -> String {
        let mut link = String::new();
        link.push_str(&self.addr_id);
        link.push(':');
        link.push_str(&self.msg_id);
        link
    }

    pub fn copy(&self) -> Self {
        Address {
            addr_id: self.addr_id.clone(),
            msg_id: self.msg_id.clone(),
        }
    }
}

pub type ClientWrap = Rc<RefCell<Client>>;

impl TryFrom<Address> for ApiAddress {
    type Error = JsValue;
    fn try_from(addr: Address) -> Result<Self> {
        ApiAddress::from_str(&addr.to_string()).map_err(|_err| JsValue::from_str("bad address"))
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
                Address::from_string(msg.link.to_string()),
                None,
                Some(Message::new(Some(hex::encode(pk.to_bytes())), p.0, m.0)),
            )),
            MessageContent::TaggedPacket {
                public_payload: p,
                masked_payload: m,
            } => payloads.push(UserResponse::new(
                Address::from_string(msg.link.to_string()),
                None,
                Some(Message::new(None, p.0, m.0)),
            )),
            MessageContent::Sequence => (),
            _ => payloads.push(UserResponse::new(
                Address::from_string(msg.link.to_string()),
                None,
                None,
            )),
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
            link: Address::from_string(cursor.link.to_string()),
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

    pub fn get_identifier(&self) -> String {
        self.identifier.clone()
    }

    pub fn get_link(&self) -> Address {
        self.cursor.link.copy()
    }

    pub fn get_seq_no(&self) -> u32 {
        self.cursor.seq_no
    }

    pub fn get_branch_no(&self) -> u32 {
        self.cursor.branch_no
    }
}

#[wasm_bindgen]
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
        let pskid = to_result(pskid_from_hex_str(&id))?;
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
    let bytes = to_result(hex::decode(hex_str))?;
    to_result(PublicKey::from_bytes(&bytes))
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

    pub fn get_identifier(&self) -> String {
        self.identifier.clone()
    }

    pub fn get_link(&self) -> Address {
        self.msgid.copy()
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

    pub fn from_strings(link: String, seq_link: Option<String>, message: Option<Message>) -> Self {
        let seq;
        if let Some(seq_link) = seq_link {
            seq = Some(Address::from_string(seq_link));
        } else {
            seq = None;
        }

        UserResponse {
            link: Address::from_string(link),
            seq_link: seq,
            message,
        }
    }

    pub fn copy(&self) -> Self {
        let mut seq = None;
        if !self.get_seq_link().eq(&Address::default()) {
            seq = Some(self.get_seq_link());
        }
        UserResponse::new(self.get_link(), seq, None)
    }

    pub fn get_link(&self) -> Address {
        let mut link = Address::default();
        link.set_addr_id(self.link.addr_id());
        link.set_msg_id(self.link.msg_id());
        link
    }

    pub fn get_seq_link(&self) -> Address {
        if self.seq_link.is_some() {
            let seq_link = self.seq_link.as_ref().unwrap();
            let mut link = Address::default();
            link.set_addr_id(seq_link.addr_id());
            link.set_msg_id(seq_link.msg_id());
            link
        } else {
            Address::default()
        }
    }

    pub fn get_message(&mut self) -> Message {
        if self.message.is_some() {
            let message = self.message.as_ref().unwrap();
            Message {
                identifier: message.identifier.clone(),
                public_payload: message.public_payload.clone(),
                masked_payload: message.masked_payload.clone(),
            }
        } else {
            Message::default()
        }
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
