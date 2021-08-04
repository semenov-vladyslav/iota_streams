use core::iter;
use iota_streams_core::{
    async_trait,
    futures::{
        self,
        executor::block_on
    },
    prelude::Box,
    Result
};

use super::Context;
use crate::command::Repeated;
use core::future::Future;

/// Repeated modifier. The actual number of repetitions must be wrapped
/// (absorbed/masked/skipped) explicitly.
#[async_trait]
impl<'a, F, I, C, Fut> Repeated<'a, I, C, Fut> for Context<F>
where
    F: 'a + Send + Sync,
    I: iter::Iterator + Send + Sync + 'a,
    <I as Iterator>::Item: Send + Sync,
    Fut: Future<Output=Result<&'a mut Self>> + Send + Sync,
    C: FnMut(&'a mut Self, <I as iter::Iterator>::Item) -> Fut + Send + Sync + 'a,
{
    async fn repeated(&'a mut self, values_iter: I, mut value_handle: C) -> Result<&'a mut Self> {
        for item in values_iter {
            self = value_handle(&mut *self, item).await?;
        }
        Ok(self)
        /*values_iter.fold(Ok(self), |rctx, item| -> Fut {
            match rctx {
                Ok(ctx) => value_handle(ctx, item),
                Err(e) => Err(e),
            }
        })*/
    }
}
