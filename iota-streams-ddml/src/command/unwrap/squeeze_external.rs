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
impl<'a, F: PRP, N: ArrayLength<u8>, IS> Squeeze<&'a mut External<NBytes<N>>> for Context<F, IS> {
    fn squeeze(&mut self, val: &'a mut External<NBytes<N>>) -> Result<&mut Self> {
        self.spongos.squeeze((val.0).as_mut_slice())?;
        Ok(self)
    }
}
