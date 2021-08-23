//! Tangle-specific transport definitions.

use core::{
    convert::{
        AsMut,
        AsRef,
    },
    fmt,
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
            U32,
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
    Error,
    Errors::{
        BadHexFormat,
        MalformedAddressString,
    },
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
        LinkedMessage,
    },
};

/// Number of bytes to be placed in each transaction (Maximum HDF Payload Count)
pub const PAYLOAD_BYTES: usize = 1090;

/// Wrapper for a tangle formatted message
#[derive(Clone)]
pub struct TangleMessage<F> {
    /// Encapsulated binary encoded message.
    pub binary: BinaryMessage<F, TangleAddress>,

    /// Timestamp is not an intrinsic part of Streams message; it's a part of the bundle.
    /// Timestamp is checked with Kerl as part of bundle essense trits.
    pub timestamp: u64,
}

impl<F> LinkedMessage<TangleAddress> for TangleMessage<F> {
    fn link(&self) -> &TangleAddress {
        self.binary.link()
    }
    fn prev_link(&self) -> &TangleAddress {
        self.binary.prev_link()
    }
}

// TODO: Use better feature to detect `chrono::Utc::new()`.
#[cfg(all(feature = "std"))] //, not(feature = "wasmbind")
                             //#[cfg(all(feature = "std"))]
impl<F> TangleMessage<F> {
    /// Create TangleMessage from BinaryMessage and add the current timestamp.
    pub fn new(msg: BinaryMessage<F, TangleAddress>) -> Self {
        Self {
            binary: msg,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        }
    }
}

// #[cfg(feature = "wasmbind")]
// impl<F> TangleMessage<F> {
// Create TangleMessage from BinaryMessage and add the current timestamp.
// pub fn new(msg: BinaryMessage<F, TangleAddress>) -> Self {
// let timestamp = js_sys::Date::new_0().value_of() as u64;
// Self {
// binary: msg,
// timestamp,
// }
// }
// }
// #[cfg(feature = "wasmbind")]
// impl<F> TangleMessage<F> {
// Create TangleMessage from BinaryMessage and add the current timestamp.
// pub fn new(msg: BinaryMessage<F, TangleAddress>) -> Self {
// Self {
// binary: msg,
// timestamp: wasm_timer::SystemTime::now()
// .duration_since(wasm_timer::SystemTime::UNIX_EPOCH)
// .unwrap()
// .as_millis() as u64,
// }
// }
// }

//#[cfg(all(not(feature = "std"), not(feature = "wasmbind")))]
#[cfg(not(feature = "std"))]
impl<F> TangleMessage<F> {
    /// Create TangleMessage from BinaryMessage and add the current timestamp.
    pub fn new(msg: BinaryMessage<F, TangleAddress>) -> Self {
        Self {
            binary: msg,
            timestamp: 0_u64,
        }
    }
}

impl<F> TangleMessage<F> {
    /// Create TangleMessage from BinaryMessage and an explicit timestamp.
    pub fn with_timestamp(msg: BinaryMessage<F, TangleAddress>, timestamp: u64) -> Self {
        Self { binary: msg, timestamp }
    }
}

/// Tangle representation of a Message Link
///
/// A `TangleAddress` is comprised of 2 distinct parts: the channel identifier
/// ([`TangleAddress::appinst`]) and the message identifier
/// ([`TangleAddress::msgid`]). The channel identifier, also refered to as
/// the channel address, is unique per channel and is common in the
/// `TangleAddress` of all messages published in it. The message identifier is
/// produced pseudo-randomly out of the the message's sequence number, the
/// previous message identifier, and other internal properties.
///
/// ## Renderings
/// ### Blake2b hash
/// A `TangleAddress` is used as index of the message over the Tangle. For that,
/// its content is hashed using [`TangleAddress::to_msg_index()`]. If the binary
/// digest of the hash needs to be encoded in hexadecimal, you can use
/// [`core::fmt::LowerHex`] or [`core::fmt::UpperHex`]:
///
/// ```
/// # use iota_streams_app::transport::tangle::TangleAddress;
/// # use iota_streams_ddml::types::NBytes;
/// #
/// # fn main() -> anyhow::Result<()> {
/// let address = TangleAddress::new([172_u8; 40][..].into(), [171_u8; 12][..].into());
/// assert_eq!(
///     address.to_msg_index().as_ref(),
///     &[
///         44, 181, 155, 1, 109, 141, 169, 177, 209, 70, 226, 18, 190, 121, 40, 44, 90, 108, 159, 109, 241, 37, 30, 0,
///         185, 80, 245, 59, 235, 75, 128, 97
///     ],
/// );
/// assert_eq!(
///     format!("{:x}", address.to_msg_index()),
///     "2cb59b016d8da9b1d146e212be79282c5a6c9f6df1251e00b950f53beb4b8061".to_string()
/// );
/// #   Ok(())
/// # }
/// ```
///
/// ### exchangeable encoding
/// In order to exchange a `TangleAddress` between channel participants, it can be encoded and decoded
/// using [`TangleAddress::to_string()`][Display] (or [`format!()`]) and [`TangleAddress::from_str`] (or
/// [`str::parse()`]). This method encodes the `TangleAddress` as a colon-separated string containing the `appinst` and
/// `msgid` in hexadecimal:
/// ```
/// # use iota_streams_app::transport::tangle::TangleAddress;
/// # use iota_streams_ddml::types::NBytes;
/// #
/// # fn main() -> anyhow::Result<()> {
/// let address = TangleAddress::new([170_u8; 40][..].into(), [255_u8; 12][..].into());
/// let address_str = address.to_string();
/// assert_eq!(
///     address_str,
///     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:ffffffffffffffffffffffff"
///         .to_string(),
/// );
/// assert_eq!(address_str.parse::<TangleAddress>()?, address);
/// #   Ok(())
/// # }
/// ```
///
/// ## Debugging
///
/// For debugging purposes, `TangleAddress` implements `Debug`, which can be triggered with the formatting `{:?}`
/// or the pretty-printed `{:#?}`. These will output `appinst` and `msgid` as decimal arrays; you can also use
/// `{:x?}` or `{:#x?}` to render them as hexadecimal arrays.
///
/// [Display]: #impl-Display
#[derive(Debug, Clone, PartialEq, Eq, Default, Hash)]
pub struct TangleAddress {
    pub appinst: AppInst,
    pub msgid: MsgId,
}

impl TangleAddress {
    pub fn new(appinst: AppInst, msgid: MsgId) -> Self {
        Self { appinst, msgid }
    }

    /// Hash the content of the TangleAddress using `Blake2b256`
    fn to_blake2b(&self) -> NBytes<U32> {
        let hasher = blake2b::Blake2b256::new();
        let hash = hasher.chain(&self.appinst).chain(&self.msgid).finalize();
        hash.into()
    }

    /// Generate the hash used to index the [`TangleMessage`] published in this address
    ///
    /// Currently this hash is computed with [Blake2b256].
    ///
    /// [Blake2b256]: https://en.wikipedia.org/wiki/BLAKE_(hash_function)#BLAKE2|Blake2b256
    pub fn to_msg_index(&self) -> NBytes<U32> {
        self.to_blake2b()
    }

    /// # Safety
    ///
    /// This function uses CStr::from_ptr which is unsafe...
    pub unsafe fn from_c_str(c_addr: *const c_char) -> *const Self {
        c_addr.as_ref().map_or(null(), |c_addr| {
            CStr::from_ptr(c_addr).to_str().map_or(null(), |addr_str| {
                Self::from_str(addr_str).map_or(null(), |addr| Box::into_raw(Box::new(addr)))
            })
        })
    }
}

/// String representation of a Tangle Link
///
/// The current string representation of a Tangle Link is the
/// colon-separated conjunction of the hex-encoded `appinst` and `msgid`:
/// `"<appinst>:<msgid>"`.
impl fmt::Display for TangleAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}:{:x}", self.appinst, self.msgid)
    }
}

/// Create a TangleAddress out of it's string representation
///
/// This method is the opposite of [`TangleAddress::to_string()`][`Display`]
/// (see [`Display`]): it expects a colon-separated string containing the
/// hex-encoded `appinst` and `msgid`.
///
/// [`Display`]: #impl-Display
impl FromStr for TangleAddress {
    type Err = Error;
    fn from_str(string: &str) -> Result<Self, Self::Err> {
        let (appinst_str, msgid_str) = string
            .split_once(':')
            .ok_or_else(|| wrapped_err!(MalformedAddressString, WrappedError(string)))?;
        let appinst = AppInst::from_str(appinst_str)
            .map_err(|e| wrapped_err!(BadHexFormat(appinst_str.into()), WrappedError(e)))?;

        let msgid =
            MsgId::from_str(msgid_str).map_err(|e| wrapped_err!(BadHexFormat(appinst_str.into()), WrappedError(e)))?;

        Ok(TangleAddress { appinst, msgid })
    }
}

impl HasLink for TangleAddress {
    type Base = AppInst;
    type Rel = MsgId;

    fn base(&self) -> &AppInst {
        &self.appinst
    }

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
/// ed25519 public key \[32\] + 64-bit additional index
pub const APPINST_SIZE: usize = 40;

/// 40 byte Application Instance identifier.
#[derive(Clone, Default, Debug, PartialEq, Eq, Hash)]
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

impl AppInst {
    /// Get the hexadecimal representation of the AppInst
    pub fn to_hex_string(&self) -> String {
        format!("{:x}", self.id)
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

/// Display AppInst with its hexadecimal representation (lower case)
impl fmt::Display for AppInst {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}", self.id)
    }
}

impl fmt::LowerHex for AppInst {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.id, f)
    }
}

impl fmt::UpperHex for AppInst {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::UpperHex::fmt(&self.id, f)
    }
}

impl AsRef<[u8]> for AppInst {
    fn as_ref(&self) -> &[u8] {
        self.id.as_ref()
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
#[derive(Clone, Default, Debug, PartialEq, Eq, Hash)]
pub struct MsgId {
    pub(crate) id: NBytes<MsgIdSize>,
}

impl MsgId {
    /// Get the hexadecimal representation of the MsgId
    pub fn to_hex_string(&self) -> String {
        format!("{:x}", self.id)
    }
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

/// Display MsgId with its hexadecimal representation (lower case)
impl fmt::Display for MsgId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}", self.id)
    }
}

impl fmt::LowerHex for MsgId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.id, f)
    }
}

impl fmt::UpperHex for MsgId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::UpperHex::fmt(&self.id, f)
    }
}

impl AsRef<[u8]> for MsgId {
    fn as_ref(&self) -> &[u8] {
        self.id.as_ref()
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
