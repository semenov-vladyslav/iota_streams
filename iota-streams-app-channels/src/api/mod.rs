/// Identifier Key storage. Used for keeping track of channel state
pub mod key_store;

/// We would need an array import in prelude, and using IntoIter with size specifying...
/// type_complexity to be determined in future issue

/// Base level api for user implementation
#[allow(clippy::ptr_arg, clippy::type_complexity)]
pub mod user;

/// Tangle-specific Channel API.
#[cfg(feature = "tangle")]
pub mod tangle;

#[derive(Clone)]
pub enum ChannelType {
    SingleBranch,
    MultiBranch,
    SingleDepth,
}

pub use iota_streams_core::psk::{
    Psk,
    PskId,
};
use iota_streams_core::{
    psk,
    sponge::prp::keccak::KeccakF1600,
};

/// Default spongos PRP.
pub type DefaultF = KeccakF1600;

/// Derive a Psk from a secret seed
pub fn psk_from_seed(seed_bytes: &[u8]) -> Psk {
    psk::psk_from_seed::<DefaultF>(seed_bytes)
}

/// Derive a PskId from a secret seed
pub fn pskid_from_psk(psk: &Psk) -> PskId {
    psk::pskid_from_psk::<DefaultF>(psk)
}

/// Derive a PskId from a secret seed
pub fn pskid_from_seed(seed_bytes: &[u8]) -> PskId {
    psk::pskid_from_seed::<DefaultF>(seed_bytes)
}

/// Create a PskId from a string or it's hash if the string is too long
pub fn pskid_from_str(id: &str) -> PskId {
    psk::pskid_from_str::<DefaultF>(id)
}
