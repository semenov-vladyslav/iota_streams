//! `Keyload` message content. This message contains key information for the set of recipients.
//!
//! Recipients are identified either by pre-shared keys or by Ed/X25519 public key identifiers.
//!
//! ```ddml
//! message Keyload {
//!     join link msgid;
//!     absorb u8 nonce[16];
//!     skip repeated {
//!         fork;
//!         mask u8 id[16];
//!         absorb external u8 psk[32];
//!         commit;
//!         mask u8 key[32];
//!     }
//!     skip repeated {
//!         fork;
//!         mask u8 xpk[32];
//!         absorb u8 eph_key[32];
//!         x25519(eph_key) u8 xkey[32];
//!         commit;
//!         mask u8 key[32];
//!     }
//!     absorb external u8 key[32];
//!     commit;
//! }
//! ```
//!
//! # Fields:
//!
//! * `nonce` -- A nonce to be used with the key encapsulated in the keyload.
//! A unique nonce allows for session keys to be reused.
//!
//! * `id` -- Key (PSK or X25519 public key) identifier.
//!
//! * `psk` -- Pre-shared key known to the author and to a legit recipient.
//!
//! * `xpk` -- Recipient's X25519 public key.
//!
//! * `eph_key` -- X25519 random ephemeral key.
//!
//! * `xkey` -- X25519 common key.
//!
//! * `key` -- Session key; a legit recipient gets it from corresponding fork.
//!
//! * `sig` -- Optional signature; allows to authenticate keyload.
//!
//! Notes:
//! 1) Keys identities are not encrypted and may be linked to recipients identities.
//! 2) Keyload is not authenticated (signed). It can later be implicitly authenticated
//!     via `SignedPacket`.

use core::convert::TryFrom;
use iota_streams_app::{
    identifier::Identifier,
    message::{
        self,
        *,
    },
};
use iota_streams_core::{
    prelude::{
        typenum::Unsigned as _,
        Vec,
    },
    psk,
    sponge::{
        prp::PRP,
        spongos,
    },
    Error,
    Result,
};
use iota_streams_core_edsig::{
    key_exchange::x25519,
    signature::ed25519,
};
use iota_streams_ddml::{
    command::*,
    io,
    link_store::{
        EmptyLinkStore,
        LinkStore,
    },
    types::*,
};

pub struct ContentWrap<'a, F, Link: HasLink, Keys> {
    pub(crate) link: &'a <Link as HasLink>::Rel,
    pub nonce: NBytes<U16>,
    pub key: NBytes<U32>,
    pub(crate) keys: Keys,
    pub(crate) sig_kp: &'a ed25519::Keypair,
    pub(crate) _phantom: core::marker::PhantomData<(F, Link)>,
}

impl<'a, F, Link, Keys> message::ContentSizeof<F> for ContentWrap<'a, F, Link, Keys>
where
    F: 'a + PRP, // weird 'a constraint, but compiler requires it somehow?!
    Link: HasLink,
    <Link as HasLink>::Rel: 'a + Eq + SkipFallback<F>,
    Keys: Clone + ExactSizeIterator<Item = (&'a Identifier, Vec<u8>)>,
{
    fn sizeof<'c>(&self, ctx: &'c mut sizeof::Context<F>) -> Result<&'c mut sizeof::Context<F>> {
        let store = EmptyLinkStore::<F, <Link as HasLink>::Rel, ()>::default();
        let repeated_keys = Size(self.keys.len());
        ctx.join(&store, self.link)?
            .absorb(&self.nonce)?
            .fork(|ctx| {
                // fork into new context in order to hash Identifiers
                ctx.absorb(repeated_keys)?
                    .repeated(self.keys.clone().into_iter(), |ctx, (id, store_id)| {
                        let ctx = id.sizeof(ctx)?;
                        ctx.fork(|ctx| {
                            // fork in order to skip the actual keyload data which may be unavailable to all recipients
                            match &id {
                                Identifier::PskId(_pskid) => ctx
                                    .absorb(External(<&NBytes<psk::PskSize>>::from(<&[u8]>::from(&store_id))))?
                                    .commit()?
                                    .mask(&self.key),
                                Identifier::EdPubKey(_pk) => ctx.x25519(
                                    &x25519::PublicKey::from(
                                        <[u8; 32]>::try_from(store_id.as_ref()).map_err(Error::msg)?,
                                    ),
                                    &self.key,
                                ),
                            }
                        })
                    })
            })?
            .absorb(External(&self.key))?
            .fork(|ctx| ctx.ed25519(self.sig_kp, HashSig))?
            .commit()?;
        Ok(ctx)
    }
}

impl<'a, F, Link, Store, Keys> message::ContentWrap<F, Store> for ContentWrap<'a, F, Link, Keys>
where
    F: 'a + PRP, // weird 'a constraint, but compiler requires it somehow?!
    Link: HasLink,
    <Link as HasLink>::Rel: 'a + Eq + SkipFallback<F>,
    Store: LinkStore<F, <Link as HasLink>::Rel>,
    Keys: Clone + ExactSizeIterator<Item = (&'a Identifier, Vec<u8>)>,
{
    fn wrap<'c, OS: io::OStream>(
        &self,
        store: &Store,
        ctx: &'c mut wrap::Context<F, OS>,
    ) -> Result<&'c mut wrap::Context<F, OS>> {
        let mut id_hash = External(NBytes::<U64>::default());
        let repeated_keys = Size(self.keys.len());
        ctx.join(store, self.link)?
            .absorb(&self.nonce)?
            .fork(|ctx| {
                // fork into new context in order to hash Identifiers
                ctx.absorb(repeated_keys)?
                    .repeated(self.keys.clone().into_iter(), |ctx, (id, store_id)| {
                        let ctx = id.wrap(store, ctx)?;
                        ctx.fork(|ctx| {
                            // fork in order to skip the actual keyload data which may be unavailable to all recipients
                            match &id {
                                Identifier::PskId(_pskid) => ctx
                                    .absorb(External(<&NBytes<psk::PskSize>>::from(<&[u8]>::from(&store_id))))?
                                    .commit()?
                                    .mask(&self.key),
                                Identifier::EdPubKey(_pk) => ctx.x25519(
                                    &x25519::PublicKey::from(
                                        <[u8; 32]>::try_from(store_id.as_ref()).map_err(Error::msg)?,
                                    ),
                                    &self.key,
                                ),
                            }
                        })
                    })?
                    .commit()?
                    .squeeze(&mut id_hash)
            })?
            .absorb(External(&self.key))?
            .fork(|ctx| ctx.absorb(&id_hash)?.ed25519(self.sig_kp, HashSig))?
            .commit()?;
        Ok(ctx)
    }
}

// This whole mess with `'a` and `LookupArg: 'a` is needed in order to allow `LookupPsk`
// and `LookupKeSk` avoid copying and return `&'a Psk` and `&'a ed25519::PublicKey`.
pub struct ContentUnwrap<'a, F, Link: HasLink, LookupArg: 'a, LookupPsk, LookupKeSk> {
    pub link: <Link as HasLink>::Rel,
    pub nonce: NBytes<U16>, // TODO: unify with spongos::Spongos::<F>::NONCE_SIZE)
    pub(crate) lookup_arg: &'a LookupArg,
    pub(crate) lookup_psk: LookupPsk,

    #[allow(dead_code)]
    pub(crate) ke_pk: ed25519::PublicKey,
    pub(crate) lookup_ke_sk: LookupKeSk,
    pub(crate) key_ids: Vec<Identifier>,
    pub key: Option<NBytes<U32>>, // TODO: unify with spongos::Spongos::<F>::KEY_SIZE
    pub(crate) sig_pk: &'a ed25519::PublicKey,
    _phantom: core::marker::PhantomData<(F, Link)>,
}

impl<'a, F, Link, LookupArg, LookupPsk, LookupKeSk> ContentUnwrap<'a, F, Link, LookupArg, LookupPsk, LookupKeSk>
where
    F: PRP,
    Link: HasLink,
    <Link as HasLink>::Rel: Eq + Default + SkipFallback<F>,
    LookupArg: 'a,
    LookupPsk: for<'b> Fn(&'b LookupArg, &Identifier) -> Option<psk::Psk>,
    LookupKeSk: for<'b> Fn(&'b LookupArg, &Identifier) -> Option<&'b x25519::StaticSecret>,
{
    pub fn new(
        lookup_arg: &'a LookupArg,
        lookup_psk: LookupPsk,
        lookup_ke_sk: LookupKeSk,
        sig_pk: &'a ed25519::PublicKey,
    ) -> Self {
        Self {
            link: <<Link as HasLink>::Rel as Default>::default(),
            nonce: NBytes::default(),
            lookup_arg,
            lookup_psk,
            ke_pk: ed25519::PublicKey::default(),
            lookup_ke_sk,
            key_ids: Vec::new(),
            key: None,
            sig_pk,
            _phantom: core::marker::PhantomData,
        }
    }
}

impl<'a, F, Link, Store, LookupArg, LookupPsk, LookupKeSk> message::ContentUnwrap<F, Store>
    for ContentUnwrap<'a, F, Link, LookupArg, LookupPsk, LookupKeSk>
where
    F: PRP + Clone,
    Link: HasLink,
    <Link as HasLink>::Rel: Eq + Default + SkipFallback<F>,
    Store: LinkStore<F, <Link as HasLink>::Rel>,
    LookupArg: 'a,
    LookupPsk: for<'b> Fn(&'b LookupArg, &Identifier) -> Option<psk::Psk>,
    LookupKeSk: for<'b> Fn(&'b LookupArg, &Identifier) -> Option<&'b x25519::StaticSecret>,
{
    fn unwrap<'c, IS: io::IStream>(
        &mut self,
        store: &Store,
        ctx: &'c mut unwrap::Context<F, IS>,
    ) -> Result<&'c mut unwrap::Context<F, IS>> {
        let mut id_hash = External(NBytes::<U64>::default());
        let mut repeated_keys = Size(0);
        ctx.join(store, &mut self.link)?.absorb(&mut self.nonce)?.fork(|ctx| {
            ctx.absorb(&mut repeated_keys)?
                .repeated(repeated_keys, |ctx| {
                    let (id, ctx) = Identifier::unwrap_new(store, ctx)?;
                    ctx.fork(|ctx| {
                        match &id {
                            Identifier::PskId(_id) => {
                                if let Some(psk) = (self.lookup_psk)(self.lookup_arg, &id) {
                                    let mut key = NBytes::<U32>::default();
                                    ctx.absorb(External(<&NBytes<psk::PskSize>>::from(&psk)))?
                                        .commit()?
                                        .mask(&mut key)?;
                                    self.key = Some(key);
                                    self.key_ids.push(id);
                                    Ok(ctx)
                                } else {
                                    self.key_ids.push(id);
                                    // Just drop the rest of the forked message so not to waste Spongos operations
                                    let n = Size(spongos::KeySize::<F>::USIZE);
                                    ctx.drop(n)
                                }
                            }
                            Identifier::EdPubKey(ke_pk) => {
                                if let Some(ke_sk) = (self.lookup_ke_sk)(self.lookup_arg, &id) {
                                    let mut key = NBytes::<U32>::default();
                                    ctx.x25519(ke_sk, &mut key)?;
                                    self.key = Some(key);
                                    // Save the relevant public key
                                    self.ke_pk = ke_pk.0;
                                    self.key_ids.push(id);
                                    Ok(ctx)
                                } else {
                                    self.key_ids.push(id);
                                    // Just drop the rest of the forked message so not to waste Spongos operations
                                    // TODO: key length
                                    let n = Size(64);
                                    ctx.drop(n)
                                }
                            }
                        }
                    })
                })?
                .commit()?
                .squeeze(&mut id_hash)
        })?;

        if let Some(ref key) = self.key {
            ctx.absorb(External(key))?
                .fork(|ctx| ctx.absorb(&id_hash)?.ed25519(self.sig_pk, HashSig))?
                .commit()
        } else {
            // Allow key not found, no key situation must be handled outside, there's a use-case for that
            Ok(ctx)
        }
    }
}

// TODO: add test cases: 0,1,2 pks + 0,1,2 psks + key found/notfound + unwrap modify/fuzz to check sig does work
