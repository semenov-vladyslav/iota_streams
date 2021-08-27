use iota_streams_core::Result;

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
};

/// Signature size depends on Merkle tree height.
impl<F: PRP, OS: io::OStream> Ed25519<&ed25519::SecretKey, &External<NBytes<U64>>> for Context<F, OS> {
    fn ed25519(&mut self, sk: &ed25519::SecretKey, hash: &External<NBytes<U64>>) -> Result<&mut Self> {
        // TODO: ed25519 "IOTAStreams" context
        let signature = sk.sign((hash.0).as_slice());
        self.stream
            .try_advance(ed25519::SIGNATURE_LENGTH)?
            .copy_from_slice(&signature.to_bytes());
        Ok(self)
    }
}

impl<F: PRP, OS: io::OStream> Ed25519<&ed25519::SecretKey, HashSig> for Context<F, OS> {
    fn ed25519(&mut self, sk: &ed25519::SecretKey, _hash: HashSig) -> Result<&mut Self> {
        // Squeeze external and commit cost nothing in the stream.
        let mut hash = External(NBytes::<U64>::default());
        self.commit()?.squeeze(&mut hash)?.ed25519(sk, &hash)
    }
}
