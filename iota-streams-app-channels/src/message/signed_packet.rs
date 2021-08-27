//! `SignedPacket` message content. This message contains a plain and masked payload, signed by the
//! sender.
//!
//! The message may be linked to any other message in the channel. It contains both plain and masked
//! payloads. Each packet is signed by the sender's corresponding ed25519 private key for
//! validation.
//!
//! ```ddml
//! message SignedPacket {
//!     join link msgid;
//!     absorb bytes public_payload;
//!     mask bytes masked_payload;
//!     commit;
//!     squeeze external byte hash[78];
//!     mssig(hash) sig;
//! }
//! ```
//!
//! # Fields
//!
//! * `msgid` -- link to the base message.
//!
//! * `public_payload` -- public part of payload.
//!
//! * `masked_payload` -- masked part of payload.
//!
//! * `hash` -- hash value to be signed.
//!
//! * `sig` -- message signature generated with the senders private key.

use iota_streams_app::message::{
    self,
    HasLink,
};
use iota_streams_core::{
    signature::ed25519,
    sponge::prp::PRP,
    Result,
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
    <Link as HasLink>::Rel: 'a,
{
    pub(crate) link: &'a <Link as HasLink>::Rel,
    pub(crate) public_payload: &'a Bytes,
    pub(crate) masked_payload: &'a Bytes,
    pub(crate) sig_sk: &'a ed25519::SecretKey,
    pub(crate) _phantom: core::marker::PhantomData<(F, Link)>,
}

impl<'a, F, Link> message::ContentSizeof<F> for ContentWrap<'a, F, Link>
where
    F: PRP,
    Link: HasLink,
    <Link as HasLink>::Rel: 'a + Eq + SkipFallback<F>,
{
    fn sizeof<'c>(&self, ctx: &'c mut sizeof::Context<F>) -> Result<&'c mut sizeof::Context<F>> {
        let store = EmptyLinkStore::<F, <Link as HasLink>::Rel, ()>::default();
        ctx.join(&store, self.link)?
            .commit()?
            .absorb(&self.sig_sk.public_key())?
            .absorb(self.public_payload)?
            .mask(self.masked_payload)?
            .ed25519(self.sig_sk, HashSig)?;
        // TODO: Is both public and masked payloads are ok? Leave public only or masked only?
        Ok(ctx)
    }
}

impl<'a, F, Link, Store> message::ContentWrap<F, Store> for ContentWrap<'a, F, Link>
where
    F: PRP,
    Link: HasLink,
    <Link as HasLink>::Rel: 'a + Eq + SkipFallback<F>,
    Store: LinkStore<F, <Link as HasLink>::Rel>,
{
    fn wrap<'c, OS: io::OStream>(
        &self,
        store: &Store,
        ctx: &'c mut wrap::Context<F, OS>,
    ) -> Result<&'c mut wrap::Context<F, OS>> {
        ctx.join(store, self.link)?
            .commit()?
            .absorb(&self.sig_sk.public_key())?
            .absorb(self.public_payload)?
            .mask(self.masked_payload)?
            .ed25519(self.sig_sk, HashSig)?;
        Ok(ctx)
    }
}

pub struct ContentUnwrap<F, Link: HasLink> {
    pub(crate) link: <Link as HasLink>::Rel,
    pub(crate) public_payload: Bytes,
    pub(crate) masked_payload: Bytes,
    pub(crate) sig_pk: ed25519::PublicKey,
    pub(crate) _phantom: core::marker::PhantomData<(F, Link)>,
}

impl<F, Link> Default for ContentUnwrap<F, Link>
where
    Link: HasLink,
    <Link as HasLink>::Rel: Eq + Default + SkipFallback<F>,
{
    fn default() -> Self {
        Self {
            link: <<Link as HasLink>::Rel as Default>::default(),
            public_payload: Bytes::default(),
            masked_payload: Bytes::default(),
            sig_pk: ed25519::PublicKey::try_from_bytes([0; 32]).unwrap(),
            _phantom: core::marker::PhantomData,
        }
    }
}

impl<F, Link, Store> message::ContentUnwrap<F, Store> for ContentUnwrap<F, Link>
where
    F: PRP,
    Link: HasLink,
    <Link as HasLink>::Rel: Eq + Default + SkipFallback<F>,
    Store: LinkStore<F, <Link as HasLink>::Rel>,
{
    fn unwrap<'c, IS: io::IStream>(
        &mut self,
        store: &Store,
        ctx: &'c mut unwrap::Context<F, IS>,
    ) -> Result<&'c mut unwrap::Context<F, IS>> {
        ctx.join(store, &mut self.link)?
            .commit()?
            .absorb(&mut self.sig_pk)?
            .absorb(&mut self.public_payload)?
            .mask(&mut self.masked_payload)?
            .ed25519(&self.sig_pk, HashSig)?;
        Ok(ctx)
    }
}
