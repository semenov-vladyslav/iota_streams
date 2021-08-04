use iota_streams_core::Result;

use super::Context;
use crate::{
    command::Fork,
    io,
};
use iota_streams_core::{
    async_trait,
    prelude::Box,
    sponge::prp::PRP,
    futures::task::Spawn,
};
use core::future::Future;

#[async_trait]
impl<'a, C, F: 'a + PRP, OS: 'a + io::OStream, Fut> Fork<'a, C, Fut> for Context<F, OS>
where
    Fut: Future<Output=Result<&'a mut Self>> + Send,
    C: 'a + FnMut(&'a mut Self) -> Fut + Send,
{
    async fn fork(&'a mut self, mut cont: C) -> Result<&'a mut Self> {
        let saved_fork = self.spongos.fork();
        self = cont(&mut *self).await?;
        self.spongos = saved_fork;
        Ok(self)
    }
}
/*
impl<C, F: PRP, OS: io::OStream> Fork<C> for Context<F, OS>
    where
        C: for<'a> FnMut(&'a mut Self) -> Result<&'a mut Self> + Send,
{
    fn fork(&mut self, mut cont: C) -> Result<&mut Self> {
        let saved_fork = self.spongos.fork();
        cont(&mut *self)?;
        self.spongos = saved_fork;
        Ok(self)
    }
}*/
