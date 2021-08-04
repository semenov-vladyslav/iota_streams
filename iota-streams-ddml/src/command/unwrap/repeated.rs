use iota_streams_core::Result;

use super::Context;
use crate::{
    command::Repeated,
    io,
    types::Size,
};
use iota_streams_core::{
    async_trait,
    prelude::Box,
    sponge::prp::PRP
};
use core::future::Future;

#[async_trait]
impl<'a, C, F: 'a + PRP, IS: 'a + io::IStream, Fut> Repeated<'a, Size, C, Fut> for Context<F, IS>
where
    Fut: Future<Output=Result<&'a mut Self>> + Send + Sync,
    C: 'a + FnMut(&'a mut Self) -> Fut + Send + Sync,
{
    async fn repeated(&'a mut self, n: Size, mut value_handle: C) -> Result<&'a mut Self> {
        let mut ctx = self;
        for _ in 0..(n.0) {
            ctx = value_handle(ctx).await?;
        }
        Ok(ctx)
    }
}
