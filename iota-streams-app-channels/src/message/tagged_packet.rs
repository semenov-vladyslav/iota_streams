//! `TaggedPacket` message content. The message has a plain and masked payload and is authenticated
//! with MAC.
//!
//! The message may be linked to any other message in the channel and can be published by any
//! participant in a channel.
//!
//! ```ddml
//! message TaggedPacket {
//!     join link msgid;
//!     absorb bytes public_payload;
//!     mask bytes masked_payload;
//!     commit;
//!     squeeze byte mac[32];
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
//! * `mac` -- MAC of the message.

use iota_streams_app::message::{
    self,
    HasLink,
};
use iota_streams_core::{
    sponge::{
        prp::PRP,
        TAG_SIZE,
    },
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
        let mac = Mac(TAG_SIZE);
        ctx.join(&store, self.link)?
            .commit()?
            .absorb(self.public_payload)?
            .mask(self.masked_payload)?
            .commit()?
            .squeeze(&mac)?;
        // TODO: Is bot public and masked payloads are ok? Leave public only or masked only?
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
        let mac = Mac(TAG_SIZE);
        ctx.join(store, self.link)?
            .commit()?
            .absorb(self.public_payload)?
            .mask(self.masked_payload)?
            .commit()?
            .squeeze(&mac)?;
        Ok(ctx)
    }
}

// TODO: factor out `public_payload` and `masked_payload` into `pub struct Content`
pub struct ContentUnwrap<F, Link: HasLink> {
    pub(crate) link: <Link as HasLink>::Rel,
    pub(crate) public_payload: Bytes,
    pub(crate) masked_payload: Bytes,
    pub(crate) _phantom: core::marker::PhantomData<(F, Link)>,
}

impl<F, Link> ContentUnwrap<F, Link>
where
    Link: HasLink,
    <Link as HasLink>::Rel: Eq + Default + SkipFallback<F>,
{
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            link: <<Link as HasLink>::Rel as Default>::default(),
            public_payload: Bytes::default(),
            masked_payload: Bytes::default(),
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
        let mac = Mac(TAG_SIZE);
        ctx.join(store, &mut self.link)?
            .commit()?
            .absorb(&mut self.public_payload)?
            .mask(&mut self.masked_payload)?
            .commit()?
            .squeeze(&mac)?;
        Ok(ctx)
    }
}
