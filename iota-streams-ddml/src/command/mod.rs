//! DDML commands are declared as traits, a new command/trait can be added without breaking old types.
//!
//! Commands usually take arguments, different commands process arguments of different types.
//! Argument types are arguments to traits corresponding to commands.
//!
//! A number of traits can be implemented for a certain type -- Context.
//! Context stores all related information needed to perform the command:
//! IO buffer, Spongos state, private keys, trusted public keys, etc..
//!
//! Trait methods take `&mut self` as input and return `Result<&mut Self>` as output
//! which allows to use the same context in a chain of multiple commands.
//!
//! A command semantic changes depending on which operation is being performed -- Wrap or Unwrap.
//! Beside semantic the type of arguments can also change: input arguments to a wrap
//! command are usually passed by a reference `&T` and output arguments to an unwrap
//! command are passed by a mutable reference `&mut T`.
//!
//! Although Wrap and Unwrap are the two operations related to processing messages,
//! the traits can be implemented for other Contexts and needs. For example, the size of
//! the buffer needed to wrap a message is implemented this way (see `sizeof` module).
//!
//! Command traits are implemented in modules `sizeof`, `wrap`, `unwrap`.

use iota_streams_core::Result;

use iota_streams_core::{
    println,
    Errors,
};

/// Absorb command. Trinary representation of the field is absorbed into Spongos state.
/// External fields are not encoded in the trinary stream. Non-trinary field is
/// an input argument in Wrap command and an output argument in Unwrap command.
pub trait Absorb<Type> {
    fn absorb(&mut self, field: Type) -> Result<&mut Self>;
}

/// Squeeze command. Trinary representation of the field is squeezed from Spongos state.
/// The command supports fields of `tryte [n]` type (`NTryte`) and is usually used as
/// MAC or externally stored hash value to be signed.
pub trait Squeeze<Type> {
    fn squeeze(&mut self, field: Type) -> Result<&mut Self>;
}

/// Mask command. Trinary representation is encrypted in Wrap command and decrypted
/// in Unwrap command using Spongos.
/// Formatted fields (eg. of `size_t` type or `oneof`) are checked after decryption.
pub trait Mask<Type> {
    fn mask(&mut self, field: Type) -> Result<&mut Self>;
}

/// Skip command. Trinary representation is just encoded/decoded and is not processed with Spongos.
pub trait Skip<Type> {
    fn skip(&mut self, field: Type) -> Result<&mut Self>;
}

/// Commit command. Commit Spongos state.
pub trait Commit {
    fn commit(&mut self) -> Result<&mut Self>;
}

/// Ed25519 command. Sign/verify hash value. The signature is processed implicitly and is
/// not returned.
pub trait Ed25519<Key, Hash> {
    fn ed25519(&mut self, key: Key, hash: Hash) -> Result<&mut Self>;
}

/// X25519 command. Absorb Diffie-Hellman shared key.
pub trait X25519<SK, PK> {
    fn x25519(&mut self, sk: SK, pk: PK) -> Result<&mut Self>;
}

/// Fork command. Fork Spongos state and continue processing `cont` commands.
/// After the fork is finished the resulting Spongos state is discarded and
/// field processing continues using the saved current Spongos state.
/// The trait can be implemented for functions `Fn(&mut self) -> Result<&mut Self>`.
pub trait Fork<F> {
    fn fork(&mut self, cont: F) -> Result<&mut Self>;
}

/// Join command. Spongos state for the linked message is retrieved from the context
/// and joined with the current Spongos state.
///
/// Links are not absorbed and thus can be changed (even for different kinds of transport).
/// Although it may be non-trivial to locate a link in the middle of a message,
/// links are usually inserted at the start of message content (after header of course).
pub trait Join<L, S> {
    fn join(&mut self, store: S, link: L) -> Result<&mut Self>;
}

/// Repeated modifier.
pub trait Repeated<I, F> {
    /// `values_iter` provides some iterated values or counter.
    /// `value_handler` handles one item.
    fn repeated(&mut self, values_iter: I, value_handle: F) -> Result<&mut Self>;
}

/// Condition guard.
pub trait Guard {
    fn guard(&mut self, cond: bool, err: Errors) -> Result<&mut Self>;
}

/// Dump context info into stdout.
/// Use it like this: `ctx.dump(format_args!("checkpoint"))`
pub trait Dump {
    #[allow(unused_variables)]
    fn dump<'a>(&mut self, args: core::fmt::Arguments<'a>) -> Result<&mut Self> {
        // std::io::_print(args);
        println!("{}", args);
        Ok(self)
    }
}

/// Implementation of command traits for message size calculation.
pub mod sizeof;

/// Implementation of command traits for wrapping messages.
pub mod unwrap;

/// Implementation of command traits for unwrapping messages.
pub mod wrap;

#[cfg(test)]
mod test;
