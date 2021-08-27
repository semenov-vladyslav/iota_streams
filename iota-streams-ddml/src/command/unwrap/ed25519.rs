use super::Context;
use crate::{
    command::{
        Commit,
        Ed25519,
        Squeeze,
    },
    io,
    types::{
        External,
        HashSig,
        NBytes,
        U64,
    },
};
use iota_streams_core::{
    signature::ed25519,
    sponge::prp::PRP,
    try_or,
    Errors::SignatureMismatch,
    Result,
};

/// Recover public key.
impl<'a, F: PRP, IS: io::IStream> Ed25519<&'a ed25519::PublicKey, &'a External<NBytes<U64>>> for Context<F, IS> {
    fn ed25519(&mut self, pk: &'a ed25519::PublicKey, hash: &'a External<NBytes<U64>>) -> Result<&mut Self> {
        // TODO: ed25519 "IOTAStreams" context
        let mut bytes = [0_u8; ed25519::SIGNATURE_LENGTH];
        let slice = self.stream.try_advance(ed25519::SIGNATURE_LENGTH)?;
        bytes.copy_from_slice(slice);
        let signature = ed25519::Signature::from_bytes(bytes);
        try_or!(pk.verify(&signature, (hash.0).as_slice()), SignatureMismatch)?;
        Ok(self)
    }
}

impl<'a, F: PRP, IS: io::IStream> Ed25519<&'a ed25519::PublicKey, HashSig> for Context<F, IS> {
    fn ed25519(&mut self, pk: &'a ed25519::PublicKey, _hash: HashSig) -> Result<&mut Self> {
        let mut hash = External(NBytes::<U64>::default());
        self.commit()?.squeeze(&mut hash)?.ed25519(pk, &hash)
    }
}
