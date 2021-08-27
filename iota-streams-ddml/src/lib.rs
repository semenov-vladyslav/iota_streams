//! DDML is a data description language extended with commands for cryptographic processing.
//! DDML is implemented as an EDSL in rust.

#![no_std]

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

/// DDML command traits.
pub mod command;

/// Abstractions for input/output buffers. It does not support the actual IO.
pub mod io;

/// DDML specific types.
pub mod types;

/// LinkStore trait and impls.
#[allow(clippy::type_complexity)]
pub mod link_store;
