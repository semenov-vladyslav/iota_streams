use core::cell::Ref;
use iota_streams_core::Result;

use super::*;
use iota_streams_core::{
    sponge::prp::PRP,
    try_or,
    Errors::OutputStreamNotFullyConsumed,
};
use iota_streams_ddml::{
    command::{
        sizeof,
        wrap,
    },
    link_store::LinkStore,
    types::*,
};
use iota_streams_core::prelude::{MutexGuard, Mutex};
use core::borrow::BorrowMut;

/// Message context prepared for wrapping.
pub struct PreparedMessage<'a, F, Link: Default, Store: 'a, Content> {
    store: &'a MutexGuard<'a, Store>,
    pub header: HDF<Link>,
    pub content: PCF<Content>,
    _phantom: core::marker::PhantomData<F>,
}

impl<'a, F, Link: Default, Store: 'a, Content> PreparedMessage<'a, F, Link, Store, Content> {
    pub fn new(store: &'a MutexGuard<'a, Store>, header: HDF<Link>, content: Content) -> Self {
        let content = pcf::PCF::new_final_frame()
            .with_payload_frame_num(1)
            .unwrap()
            .with_content(content);

        Self {
            store,
            header,
            content,
            _phantom: core::marker::PhantomData,
        }
    }
}

impl<'a, F, Link, Store, Content> PreparedMessage<'a, F, Link, Store, Content>
where
    F: PRP,
    Link: HasLink + AbsorbExternalFallback<F> + Clone + Default + Send + Sync,
    <Link as HasLink>::Rel: Eq + SkipFallback<F>,
    Store: 'a + LinkStore<F, <Link as HasLink>::Rel> + Send + Sync,
    HDF<Link>: ContentWrap<F, Store>,
    Content: ContentWrap<F, Store> + Send + Sync,
{
    pub async fn wrap(&self) -> Result<WrappedMessage<F, Link>> {
        let buf_size = {
            let mut ctx = sizeof::Context::<F>::new();
            self.header.sizeof(&mut ctx).await?;
            self.content.sizeof(&mut ctx).await?;
            ctx.get_size()
        };

        let mut buf = vec![0; buf_size];

        let spongos = {
            let mut ctx = wrap::Context::new(&mut buf[..]);
            self.header.wrap(&*self.store, &mut ctx).await?;
            self.content.wrap(&*self.store, &mut ctx).await?;
            try_or!(ctx.stream.is_empty(), OutputStreamNotFullyConsumed(ctx.stream.len()))?;
            ctx.spongos
        };

        Ok(WrappedMessage {
            wrapped: WrapState {
                link: self.header.link.clone(),
                spongos,
            },
            message: BinaryMessage {
                link: self.header.link.clone(),
                prev_link: Link::default(),
                body: buf.into(),
            },
        })
    }
}
