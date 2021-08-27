use iota_streams_core::Result;

use super::Context;
use crate::{
    command::Skip,
    types::{
        sizeof_sizet,
        ArrayLength,
        Bytes,
        Fallback,
        NBytes,
        Size,
        SkipFallback,
        Uint16,
        Uint32,
        Uint64,
        Uint8,
    },
};

/// Skipped values are just encoded.
/// All Uint8 values are encoded with 1 byte.
impl<F> Skip<&Uint8> for Context<F> {
    fn skip(&mut self, _u: &Uint8) -> Result<&mut Self> {
        self.size += 1;
        Ok(self)
    }
}

/// All Uint8 values are encoded with 1 byte.
impl<F> Skip<Uint8> for Context<F> {
    fn skip(&mut self, u: Uint8) -> Result<&mut Self> {
        self.skip(&u)
    }
}

/// Skipped values are just encoded.
/// All Uint16 values are encoded with 2 bytes.
impl<F> Skip<&Uint16> for Context<F> {
    fn skip(&mut self, _u: &Uint16) -> Result<&mut Self> {
        self.size += 2;
        Ok(self)
    }
}

/// All Uint16 values are encoded with 2 bytes.
impl<F> Skip<Uint16> for Context<F> {
    fn skip(&mut self, u: Uint16) -> Result<&mut Self> {
        self.skip(&u)
    }
}

/// Skipped values are just encoded.
/// All Uint32 values are encoded with 4 bytes.
impl<F> Skip<&Uint32> for Context<F> {
    fn skip(&mut self, _u: &Uint32) -> Result<&mut Self> {
        self.size += 4;
        Ok(self)
    }
}

/// All Uint32 values are encoded with 4 bytes.
impl<F> Skip<Uint32> for Context<F> {
    fn skip(&mut self, u: Uint32) -> Result<&mut Self> {
        self.skip(&u)
    }
}

/// Skipped values are just encoded.
/// All Uint64 values are encoded with 8 bytes.
impl<F> Skip<&Uint64> for Context<F> {
    fn skip(&mut self, _u: &Uint64) -> Result<&mut Self> {
        self.size += 8;
        Ok(self)
    }
}

/// All Uint64 values are encoded with 8 bytes.
impl<F> Skip<Uint64> for Context<F> {
    fn skip(&mut self, u: Uint64) -> Result<&mut Self> {
        self.skip(&u)
    }
}

/// Size has var-size encoding.
impl<F> Skip<&Size> for Context<F> {
    fn skip(&mut self, size: &Size) -> Result<&mut Self> {
        self.size += sizeof_sizet(size.0);
        Ok(self)
    }
}

/// Size has var-size encoding.
impl<F> Skip<Size> for Context<F> {
    fn skip(&mut self, size: Size) -> Result<&mut Self> {
        self.skip(&size)
    }
}

/// `bytes` is encoded with `sizeof_sizet(n) + n` bytes.
impl<'a, F> Skip<&'a Bytes> for Context<F> {
    fn skip(&mut self, bytes: &'a Bytes) -> Result<&mut Self> {
        self.size += sizeof_sizet((bytes.0).len()) + (bytes.0).len();
        Ok(self)
    }
}

/// `bytes` is encoded with `sizeof_sizet(n) + n` bytes.
impl<F> Skip<Bytes> for Context<F> {
    fn skip(&mut self, bytes: Bytes) -> Result<&mut Self> {
        self.skip(&bytes)
    }
}

/// `byte [n]` is encoded with `n` bytes.
impl<'a, F, N: ArrayLength<u8>> Skip<&'a NBytes<N>> for Context<F> {
    fn skip(&mut self, _nbytes: &'a NBytes<N>) -> Result<&mut Self> {
        self.size += N::USIZE;
        Ok(self)
    }
}

/// `byte [n]` is encoded with `n` bytes.
impl<F, N: ArrayLength<u8>> Skip<NBytes<N>> for Context<F> {
    fn skip(&mut self, nbytes: NBytes<N>) -> Result<&mut Self> {
        self.skip(&nbytes)
    }
}

impl<'a, F, T: 'a + SkipFallback<F>> Skip<&'a Fallback<T>> for Context<F> {
    fn skip(&mut self, val: &'a Fallback<T>) -> Result<&mut Self> {
        (val.0).sizeof_skip(self)?;
        Ok(self)
    }
}
