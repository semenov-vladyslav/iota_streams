use crate::prelude::generic_array::{
    ArrayLength,
    GenericArray,
};

/// Pseudo-random permutation.
///
/// Actually, it may be non-bijective as the inverse transform is not used in sponge construction.
#[allow(clippy::upper_case_acronyms)]
pub trait PRP: Sized + Default + Clone + Send + Sync //+ From<Vec<u8>> + Into<Vec<u8>>
{
    /// Size of the outer state in bytes.
    /// In other words, size of data chunk that PRP can process in one transform.
    type RateSize: ArrayLength<u8>;

    /// Size of the inner state in bits, determines the security of sponge constructions.
    /// Other sizes such as sizes of hash/key/nonce/etc. are derived from the capacity.
    type CapacitySize: ArrayLength<u8>;

    /// Transform full state.
    fn transform(&mut self);

    /// Ref for ejecting outer state.
    fn outer(&self) -> &GenericArray<u8, Self::RateSize>;

    /// Mut ref for injecting outer state.
    fn outer_mut(&mut self) -> &mut GenericArray<u8, Self::RateSize>;

    /// Ref to inner state.
    fn inner(&self) -> &GenericArray<u8, Self::CapacitySize>;

    /// Construct state from inner part defaulting outer part.
    fn from_inner(inner: &GenericArray<u8, Self::CapacitySize>) -> Self;
}
