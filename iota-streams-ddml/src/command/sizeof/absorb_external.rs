use iota_streams_core::Result;

use super::Context;
use crate::{
    command::{
        Absorb,
        AbsorbKey,
    },
    types::{
        AbsorbExternalFallback,
        ArrayLength,
        External,
        Fallback,
        Key,
        NBytes,
        Uint16,
        Uint32,
        Uint64,
        Uint8,
    },
};

// External values are not encoded in the stream.
impl<F> Absorb<External<Uint8>> for Context<F> {
    fn absorb(&mut self, _external: External<Uint8>) -> Result<&mut Self> {
        Ok(self)
    }
}
impl<F> Absorb<External<Uint16>> for Context<F> {
    fn absorb(&mut self, _external: External<Uint16>) -> Result<&mut Self> {
        Ok(self)
    }
}
impl<F> Absorb<External<Uint32>> for Context<F> {
    fn absorb(&mut self, _external: External<Uint32>) -> Result<&mut Self> {
        Ok(self)
    }
}
impl<F> Absorb<External<Uint64>> for Context<F> {
    fn absorb(&mut self, _external: External<Uint64>) -> Result<&mut Self> {
        Ok(self)
    }
}

/// External values are not encoded in the binary stream.
impl<'a, F, N: ArrayLength<u8>> Absorb<External<&'a NBytes<N>>> for Context<F> {
    fn absorb(&mut self, _external: External<&'a NBytes<N>>) -> Result<&mut Self> {
        Ok(self)
    }
}

impl<'a, F, T: 'a + AbsorbExternalFallback<F>> Absorb<External<Fallback<&'a T>>> for Context<F> {
    fn absorb(&mut self, val: External<Fallback<&'a T>>) -> Result<&mut Self> {
        ((val.0).0).sizeof_absorb_external(self)?;
        Ok(self)
    }
}

/// `key` has variable size thus the size is encoded before the content bytes.
impl<'a, F> AbsorbKey<External<&'a Key>> for Context<F> {
    fn absorb_key(&mut self, _key: External<&'a Key>) -> Result<&mut Self> {
        self.size += 0;
        Ok(self)
    }
}

/// `key` has variable size thus the size is encoded before the content bytes.
impl<'a, F> AbsorbKey<&'a External<Key>> for Context<F> {
    fn absorb_key(&mut self, _key: &'a External<Key>) -> Result<&mut Self> {
        self.size += 0;
        Ok(self)
    }
}
