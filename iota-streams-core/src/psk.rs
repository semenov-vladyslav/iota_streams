//! Pre-shared key is a secret symmetric key shared between two parties and is used for
//! (session) key exchange.

use crate::{
    prelude::{
        generic_array::{
            typenum::{
                U16,
                U32,
            },
            GenericArray,
        },
        HashMap,
        String,
        Vec,
    },
    prng,
    sponge::{
        prp::PRP,
        spongos::Spongos,
    },
    try_or,
    wrapped_err,
    Errors,
    Result,
    WrappedError,
};

/// Size of pre-shared key identifier.
pub const PSKID_SIZE: usize = 16;
pub type PskIdSize = U16;

/// Size of pre-shared key.
pub const PSK_SIZE: usize = 32;
pub type PskSize = U32;

/// Type of pre-shared key identifiers: `byte pskid[16]`.
// TODO: Introduce NBytes type in core and make a newtype. Same for Psk.
pub type PskId = GenericArray<u8, PskIdSize>;

/// Type of pre-shared keys: `byte psk[32]`.
pub type Psk = GenericArray<u8, PskSize>;

/// Entry in a PSK container, just a convenience type synonym.
pub type IPsk<'a> = (&'a PskId, &'a Psk);

/// Container for pre-shared keys.
pub type Psks = HashMap<PskId, Psk>;

/// Container (set) of pre-shared key identifiers.
pub type PskIds = [PskId];

/// Derive a Psk from arbitrary secret seed bytes.
pub fn psk_from_seed<F: PRP>(seed_bytes: &[u8]) -> Psk {
    prng::Prng::<F>::init_with_seed(seed_bytes).gen_arr("PSK")
}

/// Derive a PskId from existing Psk.
pub fn pskid_from_psk<F: PRP>(psk: &Psk) -> PskId {
    prng::Prng::<F>::init_with_seed(psk).gen_arr("PSKID")
}

/// Derive a PskId from the same seed that was used to derive the corresponding Psk.
pub fn pskid_from_seed<F: PRP>(seed_bytes: &[u8]) -> PskId {
    pskid_from_psk::<F>(&psk_from_seed::<F>(seed_bytes))
}

/// Make a PskId from string or it's hash if the string is too long.
pub fn pskid_from_str<F: PRP>(id: &str) -> PskId {
    if id.as_bytes().len() < PSKID_SIZE {
        let mut pskid = PskId::default();
        pskid.as_mut_slice()[..id.as_bytes().len()].copy_from_slice(id.as_bytes());
        pskid
    } else {
        let mut s = Spongos::<F>::init();
        s.absorb("PSKID");
        s.absorb(id.as_bytes());
        s.commit();
        s.squeeze_arr().unwrap()
    }
}

/// Represent PskId bytes as hex string.
pub fn pskid_to_hex_string(pskid: &PskId) -> String {
    hex::encode(pskid.as_slice())
}

/// Create a PskId from hex string.
pub fn pskid_from_hex_str(hex_str: &str) -> Result<PskId> {
    let pskid_bytes =
        hex::decode(hex_str).map_err(|e| wrapped_err!(Errors::BadHexFormat(hex_str.into()), WrappedError(e)))?;
    try_or!(
        PSKID_SIZE == pskid_bytes.len(),
        Errors::LengthMismatch(PSKID_SIZE, pskid_bytes.len())
    )?;
    Ok(PskId::clone_from_slice(&pskid_bytes))
}

/// Select only pre-shared keys with given identifiers.
pub fn filter_psks<'a>(psks: &'a Psks, psk_ids: &'_ PskIds) -> Vec<IPsk<'a>> {
    psk_ids
        .iter()
        .filter_map(|psk_id| psks.get_key_value(psk_id))
        .collect::<Vec<IPsk>>()
}
