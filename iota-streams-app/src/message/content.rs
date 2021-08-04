use iota_streams_core::{
    async_trait,
    prelude::Box,
    Result,
};

use iota_streams_ddml::{
    command::{
        sizeof,
        unwrap,
        wrap,
    },
    io,
};

#[async_trait]
pub trait ContentSizeof<F> {
    async fn sizeof<'c>(&self, ctx: &'c mut sizeof::Context<F>) -> Result<&'c mut sizeof::Context<F>>;
}

#[async_trait]
pub trait ContentWrap<F, Store>: ContentSizeof<F> {
    async fn wrap<'c, OS: io::OStream + Send + Sync>(
        &self,
        store: &Store,
        ctx: &'c mut wrap::Context<F, OS>,
    ) -> Result<&'c mut wrap::Context<F, OS>>;
}

#[async_trait]
pub trait ContentUnwrap<F, Store>: Send {
    async fn unwrap<'c, IS: io::IStream + Send + Sync>(
        &mut self,
        store: &Store,
        ctx: &'c mut unwrap::Context<F, IS>,
    ) -> Result<&'c mut unwrap::Context<F, IS>>;
}

#[async_trait]
pub trait ContentUnwrapNew<F, Store>: Send
where
    Self: Sized,
{
    async fn unwrap_new<'c, IS: io::IStream + Send + Sync>(
        store: &Store,
        ctx: &'c mut unwrap::Context<F, IS>,
    ) -> Result<(Self, &'c mut unwrap::Context<F, IS>)>;
}
