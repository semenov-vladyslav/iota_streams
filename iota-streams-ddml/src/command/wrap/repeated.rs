use core::iter;
use iota_streams_core::Result;

use super::Context;
use crate::{
    command::Repeated,
    io,
};
use iota_streams_core::{
    async_trait,
    prelude::Box,
    sponge::prp::PRP,
};
use core::future::Future;

#[async_trait]
impl<'a, I, C, F: 'a + PRP, OS: 'a + io::OStream, Fut> Repeated<'a, I, C, Fut> for Context<F, OS>
where
    I: 'a + iter::Iterator + Send + Sync,
    <I as Iterator>::Item: Send + Sync,
    Fut: Future<Output=Result<&'a mut Self>> + Send + Sync,
    C: 'a + FnMut(&'a mut Self, <I as iter::Iterator>::Item) -> Fut + Send + Sync,
{
    async fn repeated(&'a mut self, values_iter: I, mut value_handle: C) -> Result<&'a mut Self> {
        for item in values_iter {
            self = value_handle(&mut *self, item).await?;
        }
        Ok(self)

/*        values_iter.fold(Ok(self), |rctx, item| -> Result<&mut Self> {
            match rctx {
                Ok(ctx) => value_handle(ctx, item),
                Err(e) => Err(e),
            }
        })*/
    }
}
