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

use crate::Lookup;

use core::convert::TryFrom;
use iota_streams_app::{
    identifier::Identifier,
    message::{
        self,
        ContentUnwrapNew,
        HasLink,
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

pub struct ContentWrap<'a, F, Link>
where
    Link: HasLink,
{
    pub(crate) link: &'a <Link as HasLink>::Rel,
    pub nonce: NBytes<U16>,
    pub key: NBytes<U32>,
    pub(crate) keys: Vec<(&'a Identifier, Vec<u8>)>,
    pub(crate) sig_kp: &'a ed25519::Keypair,
    pub(crate) _phantom: core::marker::PhantomData<(F, Link)>,
}

impl<'a, F, Link> message::ContentSizeof<F> for ContentWrap<'a, F, Link>
where
    F: 'a + PRP, // weird 'a constraint, but compiler requires it somehow?!
    Link: HasLink,
    <Link as HasLink>::Rel: 'a + Eq + SkipFallback<F>,
{
    fn sizeof<'c>(&self, ctx: &'c mut sizeof::Context<F>) -> Result<&'c mut sizeof::Context<F>> {
        let store = EmptyLinkStore::<F, <Link as HasLink>::Rel, ()>::default();
        let repeated_keys = Size(self.keys.len());
        ctx.join(&store, self.link)?
            .absorb(&self.nonce)?
            .fork(|ctx| {
                // fork into new context in order to hash Identifiers
                ctx.absorb(repeated_keys)?.repeated(&self.keys, |ctx, (id, store_id)| {
                    let ctx = id.sizeof(ctx)?;
                    ctx.fork(|ctx| {
                        // fork in order to skip the actual keyload data which may be unavailable to all recipients
                        match id {
                            Identifier::PskId(_pskid) => ctx
                                .absorb(External::<&NBytes<psk::PskSize>>::from(store_id.as_slice()))?
                                .commit()?
                                .mask(&self.key),
                            Identifier::EdPubKey(_pk) => ctx.x25519(
                                &x25519::PublicKey::from(<[u8; 32]>::try_from(store_id.as_ref())?),
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

impl<'a, F, Link, Store> message::ContentWrap<F, Store> for ContentWrap<'a, F, Link>
where
    F: 'a + PRP, // weird 'a constraint, but compiler requires it somehow?!
    Link: HasLink,
    <Link as HasLink>::Rel: 'a + Eq + SkipFallback<F>,
    Store: LinkStore<F, <Link as HasLink>::Rel>,
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
                                    .absorb(External::<&NBytes<psk::PskSize>>::from(store_id.as_slice()))?
                                    .commit()?
                                    .mask(&self.key),
                                Identifier::EdPubKey(_pk) => ctx.x25519(
                                    &x25519::PublicKey::from(<[u8; 32]>::try_from(store_id.as_ref())?),
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

pub struct ContentUnwrap<'a, F, Link, PskStore, KeSkStore>
where
    Link: HasLink,
{
    pub link: <Link as HasLink>::Rel,
    pub nonce: NBytes<U16>, // TODO: unify with spongos::Spongos::<F>::NONCE_SIZE)
    pub(crate) psk_store: PskStore,
    pub(crate) ke_sk_store: KeSkStore,
    pub(crate) ke_pk: ed25519::PublicKey,
    pub(crate) key_ids: Vec<Identifier>,
    pub key: Option<NBytes<U32>>, // TODO: unify with spongos::Spongos::<F>::KEY_SIZE
    pub(crate) sig_pk: &'a ed25519::PublicKey,
    _phantom: core::marker::PhantomData<(F, Link)>,
}

impl<'a, F, Link, PskStore, KeSkStore> ContentUnwrap<'a, F, Link, PskStore, KeSkStore>
where
    F: PRP,
    Link: HasLink,
    Link::Rel: Eq + Default + SkipFallback<F>,
{
    pub fn new(psk_store: PskStore, ke_sk_store: KeSkStore, sig_pk: &'a ed25519::PublicKey) -> Self {
        Self {
            link: <<Link as HasLink>::Rel as Default>::default(),
            nonce: NBytes::default(),
            psk_store,
            ke_sk_store,
            ke_pk: ed25519::PublicKey::default(),
            key_ids: Vec::new(),
            key: None,
            sig_pk,
            _phantom: core::marker::PhantomData,
        }
    }
}

impl<'a, 'b, F, Link, LStore, PskStore, KeSkStore> message::ContentUnwrap<F, LStore>
    for ContentUnwrap<'a, F, Link, PskStore, KeSkStore>
where
    F: PRP + Clone,
    Link: HasLink,
    Link::Rel: Eq + Default + SkipFallback<F>,
    LStore: LinkStore<F, Link::Rel>,
    PskStore: for<'c> Lookup<&'c Identifier, psk::Psk>,
    KeSkStore: for<'c> Lookup<&'c Identifier, &'b x25519::StaticSecret> + 'b,
{
    fn unwrap<'c, IS>(
        &mut self,
        store: &LStore,
        ctx: &'c mut unwrap::Context<F, IS>,
    ) -> Result<&'c mut unwrap::Context<F, IS>>
    where
        IS: io::IStream,
    {
        let mut id_hash = External(NBytes::<U64>::default());
        let mut repeated_keys = Size(0);
        ctx.join(store, &mut self.link)?.absorb(&mut self.nonce)?.fork(|ctx| {
            ctx.absorb(&mut repeated_keys)?
                .repeated(repeated_keys, |ctx| {
                    let (id, ctx) = Identifier::unwrap_new(store, ctx)?;
                    ctx.fork(|ctx| {
                        match &id {
                            Identifier::PskId(_id) => {
                                if let Some(psk) = self.psk_store.lookup(&id) {
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
                                if let Some(ke_sk) = self.ke_sk_store.lookup(&id) {
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
