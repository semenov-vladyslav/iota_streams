use iota_streams_core::Result;

use super::Context;
use crate::{
    command::Repeated,
    io,
    types::Size,
};
use iota_streams_core::sponge::prp::PRP;

impl<C, F: PRP, IS: io::IStream> Repeated<Size, C> for Context<F, IS>
where
    C: for<'a> FnMut(&'a mut Self) -> Result<&'a mut Self>,
{
    fn repeated(&mut self, n: Size, mut value_handle: C) -> Result<&mut Self> {
        for _ in 0..(n.0) {
            value_handle(self)?;
        }
        Ok(self)
    }
}
