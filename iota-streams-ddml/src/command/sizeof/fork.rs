use iota_streams_core::{
    async_trait,
    prelude::Box,
    Result
};

use super::Context;
use crate::command::Fork;
use core::future::Future;

/// Forks cost nothing in the trinary stream.
#[async_trait]
impl<'a, F, C, Fut> Fork<'a, C, Fut> for Context<F>
where
    F: 'a + Send + Sync,
    Fut: Future<Output=Result<()>> + Send + Sync,
    C: 'a + FnMut(&'a mut Self) -> Fut + Send + Sync,
{
    async fn fork(mut self, mut cont: C) -> Result<()> {
        cont(&mut self).await?;
        Ok(())
    }
}
