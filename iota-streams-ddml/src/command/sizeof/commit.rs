use iota_streams_core::Result;

use super::Context;
use crate::command::Commit;

/// Commit costs nothing in the binary stream.
impl<F> Commit for Context<F> {
    fn commit(&mut self) -> Result<&mut Self> {
        Ok(self)
    }
}
