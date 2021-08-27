use iota_streams_core::Result;

use super::Context;
use crate::{
    command::Squeeze,
    io,
    types::Mac,
};
use iota_streams_core::sponge::prp::PRP;

/// External values are not encoded.
impl<'a, F: PRP, OS: io::OStream> Squeeze<&'a Mac> for Context<F, OS> {
    fn squeeze(&mut self, mac: &'a Mac) -> Result<&mut Self> {
        self.spongos.squeeze(&mut self.stream.try_advance(mac.0)?)?;
        Ok(self)
    }
}

impl<F: PRP, OS: io::OStream> Squeeze<Mac> for Context<F, OS> {
    fn squeeze(&mut self, val: Mac) -> Result<&mut Self> {
        self.squeeze(&val)
    }
}
