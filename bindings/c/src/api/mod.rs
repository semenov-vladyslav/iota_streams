use iota_streams::{
    app::{
        cstr_core::{
            CStr,
            CString,
        },
        cty::{
            c_char,
            size_t,
            uint8_t,
        },
        identifier::Identifier,
        message::Cursor,
        transport::tangle::{
            get_hash,
            MsgId,
        },
    },
    app_channels::api::{
        psk_from_seed,
        pskid_from_psk,
        tangle::*,
    },
    core::{
        prelude::*,
        psk::PskId,
    },
};

use core::ptr::{
    null,
    null_mut,
};

#[cfg(not(feature = "std"))]
static mut LAST_ERROR: String = String::new();

#[cfg(feature = "std")]
use core::cell::RefCell;

#[cfg(feature = "std")]
thread_local! {
    static LAST_ERROR: RefCell<String> = RefCell::new(String::new());
}

#[cfg(not(feature = "std"))]
fn set_last_error(e: String) {
    unsafe { LAST_ERROR = e.to_string(); }
}

#[cfg(feature = "std")]
fn set_last_error(e: String) {
    LAST_ERROR.with(|last_error| *last_error.borrow_mut() = e);
}

#[cfg(not(feature = "std"))]
#[no_mangle]
pub unsafe extern "C" fn get_last_error() -> *const c_char {
    CString::new(LAST_ERROR.clone()).map_or(null(), |e| e.into_raw())
}

#[cfg(feature = "std")]
#[no_mangle]
pub unsafe extern "C" fn get_last_error() -> *const c_char {
    LAST_ERROR.with(|last_error| CString::new(last_error.borrow().clone()).map_or(null(), |e| e.into_raw()))
}

pub fn get_channel_type(channel_type: uint8_t) -> ChannelType {
    match channel_type {
        0 => ChannelType::SingleBranch,
        1 => ChannelType::MultiBranch,
        2 => ChannelType::SingleDepth,
        _ => ChannelType::SingleBranch,
    }
}

pub(crate) fn safe_into_ptr<T>(value: T) -> *const T {
    Box::into_raw(Box::new(value))
}

pub(crate) fn safe_into_mut_ptr<T>(value: T) -> *mut T {
    Box::into_raw(Box::new(value))
}

pub(crate) fn safe_drop_ptr<T>(p: *const T) {
    unsafe {
        (p as *mut T).as_mut().map(|p| Box::from_raw(p));
    }
}

pub(crate) fn safe_drop_mut_ptr<T>(p: *mut T) {
    unsafe {
        p.as_mut().map(|p| Box::from_raw(p));
    }
}

#[repr(C)]
pub enum Err {
    Ok,
    NullArgument,
    BadArgument,
    OperationFailed,
}

fn operation_failed<E: ToString>(e: E) -> Err {
    set_last_error(e.to_string());
    Err::OperationFailed
}

#[no_mangle]
pub unsafe extern "C" fn address_from_string(c_addr: *const c_char) -> *const Address {
    Address::from_c_str(c_addr)
}

#[no_mangle]
pub unsafe extern "C" fn public_key_to_string(pubkey: *const PublicKey) -> *const c_char {
    pubkey.as_ref().map_or(null(), |pk| {
        CString::new(hex::encode(pk.as_slice())).map_or(null(), |pk| pk.into_raw())
    })
}

#[no_mangle]
pub unsafe extern "C" fn drop_address(addr: *const Address) {
    safe_drop_ptr(addr)
}

pub type PskIds = Vec<PskId>;
pub type KePks = Vec<PublicKey>;

#[no_mangle]
pub unsafe extern "C" fn pskid_as_str(pskid: *const PskId) -> *const c_char {
    pskid.as_ref().map_or(null(), |pskid| {
        CString::new(hex::encode(&pskid)).map_or(null(), |id| id.into_raw())
    })
}

#[no_mangle]
pub unsafe extern "C" fn drop_pskid(pskid: *const PskId) {
    safe_drop_ptr(pskid)
}

pub type NextMsgIds = Vec<(Identifier, Cursor<Address>)>;

#[no_mangle]
pub extern "C" fn drop_next_msg_ids(m: *const NextMsgIds) {
    safe_drop_ptr(m)
}

pub type UserState = Vec<(Identifier, Cursor<Address>)>;
#[no_mangle]
pub extern "C" fn drop_user_state(s: *const UserState) {
    safe_drop_ptr(s)
}

#[no_mangle]
pub unsafe extern "C" fn get_link_from_state(state: *const UserState, pub_key: *const PublicKey) -> *const Address {
    state.as_ref().map_or(null(), |state_ref| {
        pub_key.as_ref().map_or(null(), |pub_key| {
            let pk_id = (*pub_key).into();
            for (pk, cursor) in state_ref {
                if pk == &pk_id {
                    return safe_into_ptr(cursor.link.clone());
                }
            }
            null()
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn drop_unwrapped_message(umsg: *const UnwrappedMessage) {
    safe_drop_ptr(umsg)
}

pub type UnwrappedMessages = Vec<UnwrappedMessage>;
#[no_mangle]
pub extern "C" fn drop_unwrapped_messages(umsgs: *const UnwrappedMessages) {
    safe_drop_ptr(umsgs)
}

#[cfg(feature = "sync-client")]
pub type TransportWrap = iota_streams::app::transport::tangle::client::Client;

#[cfg(not(feature = "sync-client"))]
pub type TransportWrap = Rc<core::cell::RefCell<BucketTransport>>;

#[no_mangle]
pub extern "C" fn transport_new() -> *mut TransportWrap {
    safe_into_mut_ptr(TransportWrap::default())
}

#[no_mangle]
pub extern "C" fn transport_drop(tsp: *mut TransportWrap) {
    safe_drop_mut_ptr(tsp)
}

#[cfg(feature = "sync-client")]
#[no_mangle]
pub unsafe extern "C" fn transport_client_new_from_url(c_url: *const c_char) -> *mut TransportWrap {
    let url = CStr::from_ptr(c_url).to_str().unwrap();
    safe_into_mut_ptr(TransportWrap::new_from_url(url))
}

#[cfg(feature = "sync-client")]
mod client_details {
    use super::*;
    use iota_streams::app::transport::{
        tangle::client::{
            iota_client::{
                bee_rest_api::types::{
                    dtos::LedgerInclusionStateDto,
                    responses::MessageMetadataResponse,
                },
                MilestoneResponse,
            },
            Details as ApiDetails,
        },
        TransportDetails,
    };

    #[repr(C)]
    pub struct TransportDetails {
        metadata: MessageMetadata,
        milestone: Milestone,
    }

    impl From<ApiDetails> for TransportDetails {
        fn from(d: ApiDetails) -> Self {
            Self {
                metadata: d.metadata.into(),
                milestone: d.milestone.map_or(Milestone::default(), |m| m.into()),
            }
        }
    }

    #[repr(C)]
    pub enum LedgerInclusionState {
        Conflicting,
        Included,
        NoTransaction,
    }

    impl From<LedgerInclusionStateDto> for LedgerInclusionState {
        fn from(e: LedgerInclusionStateDto) -> Self {
            match e {
                LedgerInclusionStateDto::Conflicting => Self::Conflicting,
                LedgerInclusionStateDto::Included => Self::Included,
                LedgerInclusionStateDto::NoTransaction => Self::NoTransaction,
            }
        }
    }

    #[repr(C)]
    pub struct MessageMetadata {
        pub message_id: [u8; 129],
        pub parent_message_ids: [[u8; 129]; 2],
        pub is_solid: bool,
        pub referenced_by_milestone_index: u32,
        pub milestone_index: u32,
        pub ledger_inclusion_state: LedgerInclusionState,
        pub conflict_reason: u8,
        pub should_promote: bool,
        pub should_reattach: bool,
        pub field_flags: u32,
    }

    impl Default for MessageMetadata {
        fn default() -> Self {
            unsafe { core::mem::MaybeUninit::zeroed().assume_init() }
        }
    }

    impl From<MessageMetadataResponse> for MessageMetadata {
        fn from(m: MessageMetadataResponse) -> Self {
            let mut r = MessageMetadata::default();
            let field_flags = 0_u32
                | {
                    let s = core::cmp::min(r.message_id.len() - 1, m.message_id.as_bytes().len());
                    r.message_id[..s].copy_from_slice(&m.message_id.as_bytes()[..s]);
                    1_u32 << 0
                }
                | {
                    if 0 < m.parent_message_ids.len() {
                        let s = core::cmp::min(
                            r.parent_message_ids[0].len() - 1,
                            m.parent_message_ids[0].as_bytes().len(),
                        );
                        r.parent_message_ids[0][..s].copy_from_slice(&m.parent_message_ids[0].as_bytes()[..s]);
                    }
                    if 1 < m.parent_message_ids.len() {
                        let s = core::cmp::min(
                            r.parent_message_ids[1].len() - 1,
                            m.parent_message_ids[1].as_bytes().len(),
                        );
                        r.parent_message_ids[1][..s].copy_from_slice(&m.parent_message_ids[1].as_bytes()[..s]);
                    }
                    // TODO: support more than 2 parents
                    // assert!(!(2 < m.parent_message_ids.len()));
                    1_u32 << 1
                }
                | {
                    r.is_solid = m.is_solid;
                    1_u32 << 2
                }
                | m.referenced_by_milestone_index.map_or(0_u32, |v| {
                    r.referenced_by_milestone_index = v;
                    1_u32 << 3
                })
                | m.milestone_index.map_or(0_u32, |v| {
                    r.milestone_index = v;
                    1_u32 << 4
                })
                | m.ledger_inclusion_state.map_or(0_u32, |v| {
                    r.ledger_inclusion_state = v.into();
                    1_u32 << 5
                })
                | m.conflict_reason.map_or(0_u32, |v| {
                    r.conflict_reason = v;
                    1_u32 << 6
                })
                | m.should_promote.map_or(0_u32, |v| {
                    r.should_promote = v;
                    1_u32 << 7
                })
                | m.should_reattach.map_or(0_u32, |v| {
                    r.should_reattach = v;
                    1_u32 << 8
                });
            r.field_flags = field_flags;
            r
        }
    }

    #[repr(C)]
    pub struct Milestone {
        pub milestone_index: u32,
        pub message_id: [u8; 129],
        pub timestamp: u64,
    }

    impl Default for Milestone {
        fn default() -> Self {
            unsafe { core::mem::MaybeUninit::zeroed().assume_init() }
        }
    }

    impl From<MilestoneResponse> for Milestone {
        fn from(m: MilestoneResponse) -> Self {
            let mut r = Milestone::default();
            r.milestone_index = m.index;
            {
                let s = core::cmp::min(r.message_id.len() - 1, m.message_id.as_ref().len());
                r.message_id[..s].copy_from_slice(&m.message_id.as_ref()[..s]);
            }
            r.timestamp = m.timestamp;
            r
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn transport_get_link_details(
        r: *mut TransportDetails,
        tsp: *mut TransportWrap,
        link: *const Address,
    ) -> Err {
        r.as_mut().map_or(Err::NullArgument, |r| {
            tsp.as_mut().map_or(Err::NullArgument, |tsp| {
                link.as_ref().map_or(Err::NullArgument, |link| {
                    tsp.get_link_details(link).map_or_else(operation_failed, |d| {
                        *r = d.into();
                        Err::Ok
                    })
                })
            })
        })
    }
}

#[cfg(feature = "sync-client")]
pub use client_details::*;

#[repr(C)]
pub struct MessageLinks {
    pub msg_link: *const Address,
    pub seq_link: *const Address,
}

impl From<(Address, Option<Address>)> for MessageLinks {
    fn from(links: (Address, Option<Address>)) -> Self {
        let msg_link = safe_into_ptr(links.0);
        let seq_link = links.1.map_or(null(), safe_into_ptr);
        Self { msg_link, seq_link }
    }
}

impl MessageLinks {
    pub unsafe fn into_seq_link<'a>(self, branching: bool) -> Option<&'a Address> {
        if branching {
            self.msg_link.as_ref()
        } else {
            self.seq_link.as_ref()
        }
    }

    pub fn drop(self) {
        safe_drop_ptr(self.msg_link);
        safe_drop_ptr(self.seq_link);
    }

}

impl Default for MessageLinks {
    fn default() -> Self {
        Self {
            msg_link: null(),
            seq_link: null(),
        }
    }
}

#[no_mangle]
pub extern "C" fn drop_links(links: MessageLinks) {
    links.drop()
}

#[no_mangle]
pub unsafe extern "C" fn get_msg_link(msg_links: *const MessageLinks) -> *const Address {
    msg_links.as_ref().map_or(null(), |links| links.msg_link)
}

#[no_mangle]
pub unsafe extern "C" fn get_seq_link(msg_links: *const MessageLinks) -> *const Address {
    msg_links.as_ref().map_or(null(), |links| links.seq_link)
}



#[repr(C)]
pub struct Buffer {
    pub(crate) ptr: *const uint8_t,
    pub(crate) size: size_t,
    pub(crate) cap: size_t,
}

impl From<Vec<u8>> for Buffer {
    fn from(vec: Vec<u8>) -> Self {
        let p = core::mem::ManuallyDrop::new(vec);
        Self {
            ptr: p.as_ptr(),
            size: p.len(),
            cap: p.capacity(),
        }
    }
}

impl Default for Buffer {
    fn default() -> Self {
        Self {
            ptr: null(),
            size: 0,
            cap: 0,
        }
    }
}

impl From<Bytes> for Buffer {
    fn from(b: Bytes) -> Self {
        let p = core::mem::ManuallyDrop::new(b.0);
        Self {
            ptr: p.as_ptr(),
            size: p.len(),
            cap: p.capacity(),
        }
    }
}

impl From<Buffer> for Bytes {
    fn from(b: Buffer) -> Self {
        unsafe { Self(Vec::from_raw_parts(b.ptr as *mut u8, b.size, b.cap)) }
    }
}

impl From<Buffer> for Vec<u8> {
    fn from(b: Buffer) -> Self {
        unsafe { Vec::from_raw_parts(b.ptr as *mut u8, b.size, b.cap) }
    }
}

impl<'a> From<&'a Bytes> for Buffer {
    fn from(b: &Bytes) -> Self {
        let p = &b.0;
        Self {
            ptr: p.as_ptr(),
            size: p.len(),
            cap: p.capacity(),
        }
    }
}

impl Buffer {
    pub fn new(size: usize) -> Self {
        Bytes(Vec::with_capacity(size)).into()
    }
    pub fn drop(self) {
        let _b: Bytes = self.into();
    }
}

#[no_mangle]
pub extern "C" fn drop_buffer(b: Buffer) {
    b.drop()
}

#[repr(C)]
pub struct PacketPayloads {
    public_payload: Buffer,
    masked_payload: Buffer,
}

impl Default for PacketPayloads {
    fn default() -> Self {
        Self {
            public_payload: Buffer::default(),
            masked_payload: Buffer::default(),
        }
    }
}

impl From<(Bytes, Bytes)> for PacketPayloads {
    fn from(payloads: (Bytes, Bytes)) -> Self {
        Self {
            public_payload: Buffer::from(payloads.0),
            masked_payload: Buffer::from(payloads.1),
        }
    }
}

impl<'a> From<(&'a Bytes, &'a Bytes)> for PacketPayloads {
    fn from(payloads: (&Bytes, &Bytes)) -> Self {
        Self {
            public_payload: Buffer::from(payloads.0),
            masked_payload: Buffer::from(payloads.1),
        }
    }
}

impl From<(PublicKey, Bytes, Bytes)> for PacketPayloads {
    fn from(signed_payloads: (PublicKey, Bytes, Bytes)) -> Self {
        let payloads = (signed_payloads.1, signed_payloads.2);
        PacketPayloads::from(payloads)
    }
}

impl PacketPayloads {
    pub fn drop(self) {
        self.public_payload.drop();
        self.masked_payload.drop();
    }
}

#[no_mangle]
pub extern "C" fn drop_payloads(payloads: PacketPayloads) {
    payloads.drop()
}

#[no_mangle]
pub unsafe extern "C" fn drop_str(string: *const c_char) {
    CString::from_raw(string as *mut c_char);
}

#[no_mangle]
pub unsafe extern "C" fn get_channel_address_str(appinst: *const ChannelAddress) -> *const c_char {
    appinst.as_ref().map_or(null(), |inst| {
        CString::new(hex::encode(inst)).map_or(null(), |inst_str| inst_str.into_raw())
    })
}

#[no_mangle]
pub unsafe extern "C" fn get_msgid_str(msgid: *mut MsgId) -> *const c_char {
    msgid.as_ref().map_or(null(), |id| {
        CString::new(hex::encode(id)).map_or(null(), |id_str| id_str.into_raw())
    })
}

#[no_mangle]
pub unsafe extern "C" fn get_address_inst_str(address: *mut Address) -> *mut c_char {
    address.as_ref().map_or(null_mut(), |addr| {
        CString::new(hex::encode(addr.appinst.as_ref())).map_or(null_mut(), |inst| inst.into_raw())
    })
}

#[no_mangle]
pub unsafe extern "C" fn get_address_id_str(address: *mut Address) -> *mut c_char {
    address.as_ref().map_or(null_mut(), |addr| {
        CString::new(hex::encode(addr.msgid.as_ref())).map_or(null_mut(), |id| id.into_raw())
    })
}

#[no_mangle]
pub unsafe extern "C" fn get_address_index_str(address: *mut Address) -> *mut c_char {
    address.as_ref().map_or(null_mut(), |addr| {
        get_hash(addr.appinst.as_ref(), addr.msgid.as_ref()).map_or(null_mut(), |index| {
            CString::new(index).map_or(null_mut(), |index| index.into_raw())
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn get_payload(umsg: *const UnwrappedMessage) -> PacketPayloads {
    umsg.as_ref().map_or(PacketPayloads::default(), handle_message_contents)
}

#[no_mangle]
pub unsafe extern "C" fn get_payloads_count(umsgs: *const UnwrappedMessages) -> usize {
    umsgs.as_ref().map_or(0, |msgs| msgs.len())
}

#[no_mangle]
pub unsafe extern "C" fn get_indexed_payload(umsgs: *const UnwrappedMessages, index: size_t) -> PacketPayloads {
    umsgs.as_ref()
        .map_or(PacketPayloads::default(), |msgs| handle_message_contents(&msgs[index]))
}

fn handle_message_contents(umsg: &UnwrappedMessage) -> PacketPayloads {
    match &umsg.body {
        MessageContent::TaggedPacket {
            public_payload: p,
            masked_payload: m,
        } => (p, m).into(),

        MessageContent::SignedPacket {
            pk: _,
            public_payload: p,
            masked_payload: m,
        } => (p, m).into(),

        _ => PacketPayloads::default(),
    }
}

mod auth;
pub use auth::*;

mod sub;
pub use sub::*;