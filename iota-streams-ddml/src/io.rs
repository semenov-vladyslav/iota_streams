//! Lightweight abstraction, an equivalent of `Write` trait allowing access to slices.

use iota_streams_core::{
    panic_if_not,
    prelude::{
        hex,
        String,
    },
    try_or,
    Errors::{
        StreamAllocationExceededIn,
        StreamAllocationExceededOut,
    },
    Result,
};

/// Write
pub trait OStream {
    /// Try advance and panic in case of error.
    fn advance(&mut self, n: usize) -> &mut [u8] {
        let r = self.try_advance(n);
        panic_if_not(r.is_ok());
        r.unwrap()
    }

    /// Try put n tbits into the stream, returning a slice to the buffer.
    fn try_advance(&mut self, n: usize) -> Result<&mut [u8]>;

    /// Commit advanced buffers to the internal sink.
    fn commit(&mut self);

    /// Dump stream debug info.
    fn dump(&self) -> String {
        String::new()
    }
}

/// Read
pub trait IStream {
    /// Try advance and panic in case of error.
    fn advance(&mut self, n: usize) -> &[u8] {
        let r = self.try_advance(n);
        panic_if_not(r.is_ok());
        r.unwrap()
    }

    /// Try get n tbits from the stream, returning a slice to the buffer.
    fn try_advance(&mut self, n: usize) -> Result<&[u8]>;

    /// Commit advanced buffers from the internal sources.
    fn commit(&mut self);

    /// Dump stream debug info.
    fn dump(&self) -> String {
        String::new()
    }
}

impl<'b> OStream for &'b mut [u8] {
    fn try_advance<'a>(&'a mut self, n: usize) -> Result<&'a mut [u8]> {
        try_or!(n <= self.len(), StreamAllocationExceededOut(n, self.len()))?;
        let (head, tail) = (*self).split_at_mut(n);
        unsafe {
            *self = core::mem::transmute::<&'a mut [u8], &'b mut [u8]>(tail);
        }
        Ok(head)
    }
    fn commit(&mut self) {}
    fn dump(&self) -> String {
        hex::encode(self)
    }
}

impl<'b> IStream for &'b [u8] {
    fn try_advance<'a>(&'a mut self, n: usize) -> Result<&'a [u8]> {
        try_or!(n <= self.len(), StreamAllocationExceededIn(n, self.len()))?;
        let (head, tail) = (*self).split_at(n);
        unsafe {
            *self = core::mem::transmute::<&'a [u8], &'b [u8]>(tail);
        }
        Ok(head)
    }
    fn commit(&mut self) {}
    fn dump(&self) -> String {
        hex::encode(self)
    }
}
