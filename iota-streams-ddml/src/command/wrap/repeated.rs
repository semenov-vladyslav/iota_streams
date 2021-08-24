use core::iter;
use iota_streams_core::Result;

use super::Context;
use crate::{
    command::Repeated,
    io,
};
use iota_streams_core::sponge::prp::PRP;

impl<I, C, F: PRP, OS: io::OStream> Repeated<I, C> for Context<F, OS>
where
    I: iter::IntoIterator,
    C: for<'a> FnMut(&'a mut Self, I::Item) -> Result<&'a mut Self>,
{
    fn repeated(&mut self, values: I, mut value_handle: C) -> Result<&mut Self> {
        values.into_iter().fold(Ok(self), |rctx, item| -> Result<&mut Self> {
            match rctx {
                Ok(ctx) => value_handle(ctx, item),
                Err(e) => Err(e),
            }
        })
    }
}
