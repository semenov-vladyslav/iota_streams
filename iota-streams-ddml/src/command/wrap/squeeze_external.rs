use iota_streams_core::Result;

use super::Context;
use crate::{
    command::Squeeze,
    types::{
        ArrayLength,
        External,
        NBytes,
    },
};
use iota_streams_core::sponge::prp::PRP;

/// This is just an external tag or hash value to-be-signed.
impl<'a, F: PRP, N: ArrayLength<u8>, OS> Squeeze<&'a mut External<NBytes<N>>> for Context<F, OS> {
    fn squeeze(&mut self, external_nbytes: &'a mut External<NBytes<N>>) -> Result<&mut Self> {
        self.spongos.squeeze((external_nbytes.0).as_mut_slice())?;
        Ok(self)
    }
}

/// This is just an external tag or hash value to-be-signed.
impl<'a, F: PRP, N: ArrayLength<u8>, OS> Squeeze<External<&'a mut NBytes<N>>> for Context<F, OS> {
    fn squeeze(&mut self, external_nbytes: External<&'a mut NBytes<N>>) -> Result<&mut Self> {
        self.spongos.squeeze((external_nbytes.0).as_mut_slice())?;
        Ok(self)
    }
}
