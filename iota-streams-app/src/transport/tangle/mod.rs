//! Tangle-specific transport definitions.

use core::{
    convert::{
        AsMut,
        AsRef,
    },
    fmt,
    hash,
    ptr::null,
    str::FromStr,
};

use iota_streams_core::Result;

use iota_streams_core::{
    crypto::hashes::{
        blake2b,
        Digest,
    },
    prelude::{
        typenum::{
            U12,
            U40,
        },
        Box,
        String,
        ToString,
        Vec,
    },
    sponge::{
        prp::PRP,
        spongos::Spongos,
    },
    wrapped_err,
    Errors::BadHexFormat,
    WrappedError,
};
use iota_streams_core_edsig::signature::ed25519;
use iota_streams_ddml::{
    command::*,
    io,
    types::*,
};

use cstr_core::CStr;
use cty::c_char;

use crate::{
    identifier::Identifier,
    message::{
        BinaryMessage,
        Cursor,
        HasLink,
        LinkGenerator,
    },
};

pub type TangleMessage<F> = BinaryMessage<F, TangleAddress>;

/// Tangle representation of a Message Link
#[derive(Clone)]
pub struct TangleAddress {
    pub appinst: AppInst,
    pub msgid: MsgId,
}

impl TangleAddress {
    pub fn from_str(appinst_str: &str, msgid_str: &str) -> Result<Self> {
        let appinst = AppInst::from_str(appinst_str)
            .map_err(|e| wrapped_err!(BadHexFormat(appinst_str.into()), WrappedError(e)))?;

        let msgid =
            MsgId::from_str(msgid_str).map_err(|e| wrapped_err!(BadHexFormat(appinst_str.into()), WrappedError(e)))?;

        Ok(TangleAddress { appinst, msgid })
    }

    #[allow(clippy::inherent_to_string_shadow_display)]
    pub fn to_string(&self) -> String {
        let mut address = String::new();
        address.push_str(&self.appinst.to_string());
        address.push(':');
        address.push_str(&self.msgid.to_string());
        address
    }

    /// # Safety
    ///
    /// This function uses CStr::from_ptr which is unsafe...
    pub unsafe fn from_c_str(c_addr: *const c_char) -> *const Self {
        c_addr.as_ref().map_or(null(), |c_addr| {
            CStr::from_ptr(c_addr).to_str().map_or(null(), |addr_str| {
                let addr_vec: Vec<&str> = addr_str.split(':').collect();
                Self::from_str(addr_vec[0], addr_vec[1]).map_or(null(), |addr| Box::into_raw(Box::new(addr)))
            })
        })
    }
}

impl fmt::Debug for TangleAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{:?}:{:?}>", self.appinst, self.msgid)
    }
}

pub fn get_hash(tx_address: &[u8], tx_tag: &[u8]) -> Result<String> {
    let total = [tx_address, tx_tag].concat();
    let hash = blake2b::Blake2b256::digest(&total);
    Ok(hex::encode(&hash))
}

impl fmt::Display for TangleAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hash = get_hash(self.appinst.as_ref(), self.msgid.as_ref()).unwrap_or_default();
        write!(f, "<{}>", hash)
    }
}

impl Default for TangleAddress {
    fn default() -> Self {
        Self {
            appinst: AppInst::default(),
            msgid: MsgId::default(),
        }
    }
}

impl PartialEq for TangleAddress {
    fn eq(&self, other: &Self) -> bool {
        self.appinst == other.appinst && self.msgid == other.msgid
    }
}
impl Eq for TangleAddress {}

impl TangleAddress {
    pub fn new(appinst: AppInst, msgid: MsgId) -> Self {
        Self { appinst, msgid }
    }
}

impl hash::Hash for TangleAddress {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.appinst.hash(state);
        self.msgid.hash(state);
    }
}

impl HasLink for TangleAddress {
    type Base = AppInst;
    fn base(&self) -> &AppInst {
        &self.appinst
    }

    type Rel = MsgId;
    fn rel(&self) -> &MsgId {
        &self.msgid
    }

    fn from_base_rel(base: &AppInst, rel: &MsgId) -> Self {
        Self {
            appinst: base.clone(),
            msgid: rel.clone(),
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.appinst.as_ref().to_vec();
        bytes.extend_from_slice(self.msgid.as_ref());
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        TangleAddress::new(
            AppInst::from(&bytes[0..APPINST_SIZE]),
            MsgId::from(&bytes[APPINST_SIZE..]),
        )
    }
}

/// Default Message Identifer Generator. Used for deriving MsgId's for sequencing
#[derive(Clone)]
pub struct DefaultTangleLinkGenerator<F> {
    addr: TangleAddress,
    _phantom: core::marker::PhantomData<F>,
}

impl<F> Default for DefaultTangleLinkGenerator<F> {
    fn default() -> Self {
        Self {
            addr: TangleAddress::default(),
            _phantom: core::marker::PhantomData,
        }
    }
}

impl<F> DefaultTangleLinkGenerator<F> {
    pub fn reset_addr(&mut self, addr: TangleAddress) {
        self.addr = addr;
    }
}

impl<F: PRP> DefaultTangleLinkGenerator<F> {
    fn gen_uniform_msgid(&self, cursor: Cursor<&MsgId>) -> MsgId {
        let mut s = Spongos::<F>::init();
        s.absorb(self.addr.appinst.id.as_ref());
        s.absorb(cursor.link.id.as_ref());
        s.absorb(&cursor.branch_no.to_be_bytes());
        s.absorb(&cursor.seq_no.to_be_bytes());
        s.commit();
        let mut new = MsgId::default();
        s.squeeze(new.id.as_mut());
        new
    }
    fn gen_msgid(&self, id: &Identifier, cursor: Cursor<&MsgId>) -> MsgId {
        let mut s = Spongos::<F>::init();
        s.absorb(self.addr.appinst.id.as_ref());
        s.absorb(id.to_bytes());
        s.absorb(cursor.link.id.as_ref());
        s.absorb(&cursor.branch_no.to_be_bytes());
        s.absorb(&cursor.seq_no.to_be_bytes());
        s.commit();
        let mut new = MsgId::default();
        s.squeeze(new.id.as_mut());
        new
    }
}

impl<F: PRP> LinkGenerator<TangleAddress> for DefaultTangleLinkGenerator<F> {
    /// Used by Author to generate a new application instance: channels address and announcement message identifier
    fn gen(&mut self, pk: &ed25519::PublicKey, channel_idx: u64) {
        self.addr.appinst = AppInst::new(pk, channel_idx);
        self.addr.msgid = self.gen_msgid(&Identifier::EdPubKey((*pk).into()), Cursor::default().as_ref());
    }

    /// Used by Author to get announcement message id, it's just stored internally by link generator
    fn get(&self) -> TangleAddress {
        self.addr.clone()
    }

    /// Used by Subscriber to initialize link generator with the same state as Author
    fn reset(&mut self, announcement_link: TangleAddress) {
        self.addr = announcement_link;
    }

    /// Used by users to pseudo-randomly generate a new uniform message link from a cursor
    fn uniform_link_from(&self, cursor: Cursor<&MsgId>) -> TangleAddress {
        TangleAddress {
            appinst: self.addr.appinst.clone(),
            msgid: self.gen_uniform_msgid(cursor),
        }
    }

    /// Used by users to pseudo-randomly generate a new message link from a cursor
    fn link_from(&self, id: &Identifier, cursor: Cursor<&MsgId>) -> TangleAddress {
        TangleAddress {
            appinst: self.addr.appinst.clone(),
            msgid: self.gen_msgid(id, cursor),
        }
    }
}

pub type AppInstSize = U40;
/// ed25519 public key [32] + 64-bit additional index
pub const APPINST_SIZE: usize = 40;

/// 40 byte Application Instance identifier.
#[derive(Clone, Default)]
pub struct AppInst {
    pub(crate) id: NBytes<AppInstSize>,
}

impl AppInst {
    pub fn new(pk: &ed25519::PublicKey, channel_idx: u64) -> Self {
        let mut id = [0_u8; APPINST_SIZE];
        id[..32].copy_from_slice(pk.as_bytes());
        id[32..].copy_from_slice(&channel_idx.to_be_bytes());
        Self {
            id: unsafe { core::mem::transmute(id) },
        }
    }
}

impl<'a> From<&'a [u8]> for AppInst {
    fn from(v: &[u8]) -> AppInst {
        AppInst {
            // TODO: Implement safer TryFrom or force check for length at call site.
            id: *<&NBytes<AppInstSize>>::from(v),
        }
    }
}

impl FromStr for AppInst {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, ()> {
        // TODO: format for `s`: Bech32 (https://github.com/rust-bitcoin/rust-bech32)
        // currently lowercase hex
        hex::decode(s).map_or(Err(()), |x| {
            if x.len() == AppInstSize::USIZE {
                Ok(AppInst {
                    id: *<&NBytes<AppInstSize>>::from(&x[..]),
                })
            } else {
                Err(())
            }
        })
    }
}

impl fmt::Debug for AppInst {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.id))
    }
}

impl fmt::Display for AppInst {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.id))
    }
}

impl PartialEq for AppInst {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}
impl Eq for AppInst {}

impl AsRef<[u8]> for AppInst {
    fn as_ref(&self) -> &[u8] {
        self.id.as_ref()
    }
}

impl hash::Hash for AppInst {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

/// (appinst+msgid) is (address+tag) in terms of IOTA transaction which are stored
/// externally of message body, ie. in transaction header fields.
/// Thus the trait implemntation absorbs appinst+msgid as `external`.
impl<F: PRP> AbsorbExternalFallback<F> for TangleAddress {
    fn sizeof_absorb_external(&self, ctx: &mut sizeof::Context<F>) -> Result<()> {
        ctx.absorb(External(&self.appinst.id))?
            .absorb(External(&self.msgid.id))?;
        Ok(())
    }
    fn wrap_absorb_external<OS: io::OStream>(&self, ctx: &mut wrap::Context<F, OS>) -> Result<()> {
        ctx.absorb(External(&self.appinst.id))?
            .absorb(External(&self.msgid.id))?;
        Ok(())
    }
    fn unwrap_absorb_external<IS: io::IStream>(&self, ctx: &mut unwrap::Context<F, IS>) -> Result<()> {
        ctx.absorb(External(&self.appinst.id))?
            .absorb(External(&self.msgid.id))?;
        Ok(())
    }
}

impl<F: PRP> AbsorbFallback<F> for TangleAddress {
    fn sizeof_absorb(&self, ctx: &mut sizeof::Context<F>) -> Result<()> {
        ctx.absorb(&self.appinst.id)?.absorb(&self.msgid.id)?;
        Ok(())
    }
    fn wrap_absorb<OS: io::OStream>(&self, ctx: &mut wrap::Context<F, OS>) -> Result<()> {
        ctx.absorb(&self.appinst.id)?.absorb(&self.msgid.id)?;
        Ok(())
    }
    fn unwrap_absorb<IS: io::IStream>(&mut self, ctx: &mut unwrap::Context<F, IS>) -> Result<()> {
        ctx.absorb(&mut self.appinst.id)?.absorb(&mut self.msgid.id)?;
        Ok(())
    }
}

pub type MsgIdSize = U12;
/// Unique 12 byte identifier
pub const MSGID_SIZE: usize = 12;

/// 12 byte Message Identifier unique within application instance.
#[derive(Clone, Default)]
pub struct MsgId {
    pub(crate) id: NBytes<MsgIdSize>,
}

impl<'a> From<&'a [u8]> for MsgId {
    fn from(v: &[u8]) -> MsgId {
        MsgId {
            // TODO: Implement safer TryFrom or force check for length at call site.
            id: *<&NBytes<MsgIdSize>>::from(v),
        }
    }
}

impl FromStr for MsgId {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, ()> {
        // TODO: format for `s`: Bech32 (https://github.com/rust-bitcoin/rust-bech32)
        // currently lowercase hex
        hex::decode(s).map_or(Err(()), |x| {
            if x.len() == MsgIdSize::USIZE {
                Ok(MsgId {
                    id: *<&NBytes<MsgIdSize>>::from(&x[..]),
                })
            } else {
                Err(())
            }
        })
    }
}

impl From<NBytes<MsgIdSize>> for MsgId {
    fn from(b: NBytes<MsgIdSize>) -> Self {
        Self { id: b }
    }
}

impl fmt::Debug for MsgId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.id))
    }
}

impl fmt::Display for MsgId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.id))
    }
}

impl PartialEq for MsgId {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}
impl Eq for MsgId {}

impl AsRef<[u8]> for MsgId {
    fn as_ref(&self) -> &[u8] {
        self.id.as_ref()
    }
}

impl hash::Hash for MsgId {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

/// Msgid is used for joinable links which in the binary stream are simply
/// encoded (`skip`ped).
impl<F> SkipFallback<F> for MsgId {
    fn sizeof_skip(&self, ctx: &mut sizeof::Context<F>) -> Result<()> {
        ctx.skip(&self.id)?;
        Ok(())
    }
    fn wrap_skip<OS: io::OStream>(&self, ctx: &mut wrap::Context<F, OS>) -> Result<()> {
        ctx.skip(&self.id)?;
        Ok(())
    }
    fn unwrap_skip<IS: io::IStream>(&mut self, ctx: &mut unwrap::Context<F, IS>) -> Result<()> {
        ctx.skip(&mut self.id)?;
        Ok(())
    }
}

impl<F: PRP> AbsorbFallback<F> for MsgId {
    fn sizeof_absorb(&self, ctx: &mut sizeof::Context<F>) -> Result<()> {
        ctx.absorb(&self.id)?;
        Ok(())
    }
    fn wrap_absorb<OS: io::OStream>(&self, ctx: &mut wrap::Context<F, OS>) -> Result<()> {
        ctx.absorb(&self.id)?;
        Ok(())
    }
    fn unwrap_absorb<IS: io::IStream>(&mut self, ctx: &mut unwrap::Context<F, IS>) -> Result<()> {
        ctx.absorb(&mut self.id)?;
        Ok(())
    }
}

/// Tangle-specific Transport Client. Uses [iota_client](https://github.com/iotaledger/iota.rs/tree/dev/iota-client)
/// crate for node interfacing
#[cfg(any(feature = "sync-client", feature = "async-client", feature = "wasm-client"))]
pub mod client;
