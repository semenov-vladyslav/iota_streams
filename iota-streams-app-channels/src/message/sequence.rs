//! `Sequence` message content. These messages act as a referencing lookup point for messages in a
//! multi-branch tree.
//!
//! ```ddml
//! message Sequence {
//!     join link msgid (sequencing);
//!     absorb u8 pk[32];
//!     absorb uint seq_num;
//!     absorb link reflink (connected message);
//!     commit;
//! }
//! ```
//!
//! # Fields
//!
//! * `pk` -- publisher Ed25519 public key.
//!
//! * `seqNum` -- Sequencing state of published message.
//!
//! * `reflink` -- The msgid for the preceding message referenced by the sequenced message

use iota_streams_app::message::{
    self,
    ContentUnwrapNew,
    HasLink,
};

use iota_streams_core::{
    async_trait,
    prelude::Box,
    Result,
};

use iota_streams_app::identifier::Identifier;
use iota_streams_core::sponge::prp::PRP;
use iota_streams_core_edsig::signature::ed25519;
use iota_streams_ddml::{
    command::*,
    io,
    link_store::{
        EmptyLinkStore,
        LinkStore,
    },
    types::*,
};

pub struct ContentWrap<'a, Link>
where
    Link: HasLink,
    <Link as HasLink>::Rel: 'a,
{
    pub(crate) link: &'a <Link as HasLink>::Rel,
    pub(crate) id: Identifier,
    pub seq_num: u64,
    pub(crate) ref_link: &'a <Link as HasLink>::Rel,
}

#[async_trait]
impl<'a, F, Link> message::ContentSizeof<F> for ContentWrap<'a, Link>
where
    F: PRP,
    Link: HasLink,
    <Link as HasLink>::Rel: 'a + Eq + SkipFallback<F> + AbsorbFallback<F>,
{
    async fn sizeof<'c>(&self, ctx: &'c mut sizeof::Context<F>) -> Result<&'c mut sizeof::Context<F>> {
        let store = EmptyLinkStore::<F, <Link as HasLink>::Rel, ()>::default();
        ctx.join(&store, self.link)?;
        let ctx = self.id.sizeof(ctx).await?;
        ctx.skip(Uint64(self.seq_num))?
            .absorb(<&Fallback<<Link as HasLink>::Rel>>::from(self.ref_link))?
            .commit()?;
        Ok(ctx)
    }
}

#[async_trait]
impl<'a, F, Link, Store> message::ContentWrap<F, Store> for ContentWrap<'a, Link>
where
    F: PRP,
    Link: HasLink,
    <Link as HasLink>::Rel: 'a + Eq + SkipFallback<F> + AbsorbFallback<F>,
    Store: LinkStore<F, <Link as HasLink>::Rel>,
{
    async fn wrap<'c, OS: io::OStream + Send + Sync>(
        &self,
        store: &Store,
        ctx: &'c mut wrap::Context<F, OS>,
    ) -> Result<&'c mut wrap::Context<F, OS>> {
        ctx.join(store, self.link)?;
        let ctx = self.id.wrap(store, ctx).await?;
        ctx.skip(Uint64(self.seq_num))?
            .absorb(<&Fallback<<Link as HasLink>::Rel>>::from(self.ref_link))?
            .commit()?;
        Ok(ctx)
    }
}

pub struct ContentUnwrap<Link: HasLink> {
    pub(crate) link: <Link as HasLink>::Rel,
    pub(crate) id: Identifier,
    pub(crate) seq_num: Uint64,
    pub(crate) ref_link: <Link as HasLink>::Rel,
}

impl<Link> Default for ContentUnwrap<Link>
where
    Link: HasLink,
    <Link as HasLink>::Rel: Eq + Default,
{
    fn default() -> Self {
        Self {
            link: <<Link as HasLink>::Rel as Default>::default(),
            id: ed25519::PublicKey::default().into(),
            seq_num: Uint64(0),
            ref_link: <<Link as HasLink>::Rel as Default>::default(),
        }
    }
}

#[async_trait]
impl<F, Link, Store> message::ContentUnwrap<F, Store> for ContentUnwrap<Link>
where
    F: PRP,
    Link: HasLink,
    Store: LinkStore<F, <Link as HasLink>::Rel>,
    <Link as HasLink>::Rel: Eq + Default + SkipFallback<F> + AbsorbFallback<F>,
{
    async fn unwrap<'c, IS: io::IStream + Send + Sync>(
        &mut self,
        store: &Store,
        ctx: &'c mut unwrap::Context<F, IS>,
    ) -> Result<&'c mut unwrap::Context<F, IS>> {
        ctx.join(store, &mut self.link)?;
        let (id, ctx) = Identifier::unwrap_new(store, ctx).await?;
        self.id = id;
        ctx.skip(&mut self.seq_num)?
            .absorb(<&mut Fallback<<Link as HasLink>::Rel>>::from(&mut self.ref_link))?
            .commit()?;
        Ok(ctx)
    }
}
