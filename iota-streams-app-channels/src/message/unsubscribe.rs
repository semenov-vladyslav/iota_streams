//! `Unsubscribe` message content. This message is published by a subscriber
//! willing to unsubscribe from this channel.
//!
//! ```ddml
//! message Unsubscribe {
//!     join link msgid;
//!     commit;
//!     squeeze u8 mac[16];
//! }
//! ```
//!
//! # Fields:
//!
//! * `msgid` -- link to the `Subscribe` message published by the subscriber.
//!
//! * `mac` -- authentication tag proving knowledge of the `unsubscribe_key` from the `Subscribe` message.

use iota_streams_core::Result;
use iota_streams_app::message::{
    self,
    HasLink,
};
use iota_streams_core::{
    sponge::{
        prp::PRP,
        spongos,
    },
};
use iota_streams_ddml::{
    command::*,
    io,
    types::*,
};

pub struct ContentWrap<'a, TW, F, Link: HasLink> {
    pub(crate) link: &'a <Link as HasLink>::Rel,
    pub(crate) _phantom: std::marker::PhantomData<(TW, F, Link)>,
}

impl<'a, TW, F, Link, Store> message::ContentWrap<TW, F, Store> for ContentWrap<'a, TW, F, Link>
where
    F: PRP<TW>,
    Link: HasLink,
    <Link as HasLink>::Rel: 'a + Eq + SkipFallback<TW, F>,
    Store: LinkStore<TW, F, <Link as HasLink>::Rel>,
{
    fn sizeof<'c>(&self, ctx: &'c mut sizeof::Context<TW, F>) -> Result<&'c mut sizeof::Context<TW, F>> {
        let store = EmptyLinkStore::<TW, F, <Link as HasLink>::Rel, ()>::default();
        let mac = Mac(spongos::Spongos::<TW, F>::MAC_SIZE);
        ctx.join(&store, self.link)?.commit()?.squeeze(&mac)?;
        Ok(ctx)
    }

    fn wrap<'c, OS: io::OStream<TW>>(
        &self,
        store: &Store,
        ctx: &'c mut wrap::Context<TW, F, OS>,
    ) -> Result<&'c mut wrap::Context<TW, F, OS>> {
        let mac = Mac(spongos::Spongos::<TW, F>::MAC_SIZE);
        ctx.join(store, self.link)?.commit()?.squeeze(&mac)?;
        Ok(ctx)
    }
}

pub struct ContentUnwrap<TW, F, Link: HasLink> {
    pub link: <Link as HasLink>::Rel,
    _phantom: std::marker::PhantomData<(TW, F, Link)>,
}

impl<TW, F, Link> ContentUnwrap<TW, F, Link>
where
    Link: HasLink,
    <Link as HasLink>::Rel: Eq + Default + SkipFallback<TW, F>,
{
    pub fn new() -> Self {
        Self {
            link: <<Link as HasLink>::Rel as Default>::default(),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<TW, F, Link, Store> message::ContentUnwrap<TW, F, Store> for ContentUnwrap<TW, F, Link>
where
    F: PRP<TW>,
    Link: HasLink,
    <Link as HasLink>::Rel: Eq + Default + SkipFallback<TW, F>,
    Store: LinkStore<TW, F, <Link as HasLink>::Rel>,
{
    fn unwrap<'c, IS: io::IStream<TW>>(
        &mut self,
        store: &Store,
        ctx: &'c mut unwrap::Context<TW, F, IS>,
    ) -> Result<&'c mut unwrap::Context<TW, F, IS>> {
        let mac = Mac(spongos::Spongos::<TW, F>::MAC_SIZE);
        ctx.join(store, &mut self.link)?.commit()?.squeeze(&mac)?;
        Ok(ctx)
    }
}
