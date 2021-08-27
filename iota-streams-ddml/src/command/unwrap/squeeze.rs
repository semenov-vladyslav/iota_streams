use iota_streams_core::Result;

use super::Context;
use crate::{
    command::Squeeze,
    io,
    types::Mac,
};
use iota_streams_core::{
    sponge::prp::PRP,
    try_or,
    Errors::BadMac,
};

/// External values are not encoded. Squeeze and compare tags.
impl<'a, F: PRP, IS: io::IStream> Squeeze<&'a Mac> for Context<F, IS> {
    fn squeeze(&mut self, val: &'a Mac) -> Result<&mut Self> {
        try_or!(self.spongos.squeeze_eq(self.stream.try_advance(val.0)?)?, BadMac)?;
        Ok(self)
    }
}

impl<F: PRP, IS: io::IStream> Squeeze<Mac> for Context<F, IS> {
    fn squeeze(&mut self, val: Mac) -> Result<&mut Self> {
        self.squeeze(&val)
    }
}
