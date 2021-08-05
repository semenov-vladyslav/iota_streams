use iota_streams_core::Result;

use super::Context;
use crate::{
    command::Fork,
    io,
};
use iota_streams_core::sponge::prp::PRP;

impl<C, F: PRP, IS: io::IStream> Fork<C> for Context<F, IS>
where
    C: for<'a> FnMut(&'a mut Self) -> Result<&'a mut Self>,
{
    fn fork(&mut self, mut cont: C) -> Result<&mut Self> {
        let saved_fork = self.spongos.fork();
        cont(self)?;
        self.spongos = saved_fork;
        Ok(self)
    }
}
