use iota_streams_core::Result;

use super::Context;
use crate::command::Fork;

/// Forks cost nothing in the trinary stream.
impl<F, C> Fork<C> for Context<F>
where
    C: for<'a> FnMut(&'a mut Self) -> Result<&'a mut Self>,
{
    fn fork(&mut self, mut cont: C) -> Result<&mut Self> {
        cont(self)
    }
}
