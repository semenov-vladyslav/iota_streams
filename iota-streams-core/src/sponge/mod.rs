use crate::prelude::generic_array::{
    typenum::{
        U16,
        U32,
    },
    GenericArray,
};

pub mod prp;
pub mod spongos;

/// Sponge fixed key size in buf.
pub const KEY_SIZE: usize = 32;
pub type KeySize = U32;
pub type Key = GenericArray<u8, KeySize>;

/// Sponge fixed nonce size in buf.
pub const NONCE_SIZE: usize = 16;
pub type NonceSize = U16;
pub type Nonce = GenericArray<u8, NonceSize>;

/// Sponge fixed hash size in buf.
pub const HASH_SIZE: usize = 32;
pub type HashSize = U32;
pub type Hash = GenericArray<u8, HashSize>;

/// Sponge fixed MAC size in buf.
pub const TAG_SIZE: usize = 16;
pub type TagSize = U16;
pub type Tag = GenericArray<u8, TagSize>;

#[cfg(test)]
pub mod tests;
