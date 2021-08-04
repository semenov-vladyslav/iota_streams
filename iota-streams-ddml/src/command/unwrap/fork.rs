use iota_streams_core::Result;

use super::Context;
use crate::{
    command::Fork,
    io,
};
use iota_streams_core::{
    async_trait,
    prelude::Box,
    sponge::prp::PRP
};
use core::future::Future;

#[async_trait]
impl<'a, C, F: 'a + PRP, IS: 'a + io::IStream, Fut> Fork<'a, C, Fut> for Context<F, IS>
where
    Fut: Future<Output=Result<()>> + Send + Sync,
    C: 'a + FnMut(&'a mut Self) -> Fut + Send + Sync,
{
    async fn fork(mut self, mut cont: C) -> Result<Self> {
        let saved_fork = self.spongos.fork();
        cont(&mut self).await?;
        self.spongos = saved_fork;
        Ok(self)
    }
}
