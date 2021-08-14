use iota_streams_core::{
    prelude::{
        generic_array::GenericArray,
        typenum::{
            U168,
            U32,
        },
    },
    sponge::prp::PRP,
};

#[derive(Clone, Debug)]
pub struct KeccakF1600 {
    state: [u64; 25],
}

impl Default for KeccakF1600 {
    fn default() -> Self {
        Self { state: [0u64; 25] }
    }
}

impl KeccakF1600 {
    pub fn permutation(&mut self) {
        keccak::f1600(&mut self.state);
    }
}

impl PRP for KeccakF1600 {
    type RateSize = U168; // (1600 - 256) / 8

    type CapacitySize = U32; // 256

    fn transform(&mut self) {
        self.permutation();
    }

    fn outer(&self) -> &GenericArray<u8, Self::RateSize> {
        unsafe { &*(self.state.as_ptr() as *const GenericArray<u8, Self::RateSize>) }
    }

    fn outer_mut(&mut self) -> &mut GenericArray<u8, Self::RateSize> {
        unsafe { &mut *(self.state.as_mut_ptr() as *mut GenericArray<u8, Self::RateSize>) }
    }

    fn inner(&self) -> &GenericArray<u8, Self::CapacitySize> {
        unsafe { &*(self.state.as_ptr().add(21) as *const GenericArray<u8, Self::CapacitySize>) }
    }

    fn from_inner(inner: &GenericArray<u8, Self::CapacitySize>) -> Self {
        let mut state = [0_u64; 25];
        let i = unsafe { &mut *(state.as_mut_ptr().add(21) as *mut GenericArray<u8, Self::CapacitySize>) };
        *i = *inner;
        Self { state }
    }
}
