//! A cryptographic framework for building secure messaging applications
//!
//! This top-level crate contains references to the others that make up
//! the IOTA Streams framework.
//!
//! High-level api can be found in the [iota_streams_app_channels](iota_streams_app_channels) module.
//!
//! Message Types can be found in the [iota_streams_app_channels/message](iota_streams_app_channels::message) module.
//!
//! # Layout
//!
//! This framework is divided into the following crates:
//! - `iota_streams_app_channels`: An API for using
//! the built-in Channels Protocol
//! - `iota_streams_app`: The `message` and `transport` modules
//! for creating your own Streams applications
//! - `iota_streams_core`: Modules for the core cryptographic features used by Streamsç
//! - `iota_streams_core`: Modules for using sponge constructions with KeccakF1600B
//! and KeccakF1600T permutations
//! - `iota_streams_core`: A module for working with Edwards curve-25519 based Schnorr signature scheme and
//!   Diffie-Hellman key exchange.
//! - `iota_streams_ddml`: Modules for working with
//! the IOTA data description language called DDML, in which all Streams messages are encoded

#![no_std]

/// Streams Application layer definitions.
pub use iota_streams_app as app;
/// Streams Channel Application implementation.
pub use iota_streams_app_channels as app_channels;
pub use iota_streams_core as core;

/// Edwards curve-25519 based Schnorr signature scheme and Diffie-Hellman key exchange.
pub use iota_streams_core as core_edsig;
/// Keccak-f\[1600\]-based sponge transform.
pub use iota_streams_core as core_keccak;
/// DDML EDSL for Streams Messages.
pub use iota_streams_ddml as ddml;
