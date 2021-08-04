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
    F: 'a + Send,
    Fut: Future<Output=Result<&'a mut Self>> + Send,
    C: 'a + FnMut(&'a mut Self) -> Fut + Send,
{
    async fn fork(&'a mut self, mut cont: C) -> Result<&'a mut Self> {
        self = cont(&mut *self).await?;
        Ok(self)
    }
}
