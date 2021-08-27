//! Implementation of command traits for calculating the size for output buffer in Wrap operation.

/// Message size counting context.
#[derive(Debug)]
pub struct Context<F> {
    /// The current message size in bytes.
    size: usize,
    _phantom: core::marker::PhantomData<F>,
}

impl<F> Context<F> {
    /// Creates a new Context<F>.
    pub fn new() -> Self {
        Self {
            size: 0,
            _phantom: core::marker::PhantomData,
        }
    }
    /// Returns calculated message size.
    pub fn get_size(&self) -> usize {
        self.size
    }
}

impl<F> Default for Context<F> {
    fn default() -> Self {
        Self::new()
    }
}

mod absorb;
mod absorb_external;
mod commit;
mod dump;
mod fork;
mod join;
mod mask;
mod repeated;
mod skip;
mod squeeze;
mod squeeze_external;

mod ed25519;
mod x25519;

pub use absorb::*;
pub use absorb_external::*;
pub use commit::*;
pub use dump::*;
pub use fork::*;
pub use join::*;
pub use mask::*;
pub use repeated::*;
pub use skip::*;
pub use squeeze::*;
pub use squeeze_external::*;

pub use ed25519::*;
pub use x25519::*;
