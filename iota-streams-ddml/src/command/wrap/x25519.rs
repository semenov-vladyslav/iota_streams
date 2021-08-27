use iota_streams_core::Result;

use super::Context;
use crate::{
    command::{
        Absorb,
        Commit,
        Mask,
        X25519,
    },
    io,
    types::{
        ArrayLength,
        Key,
        NBytes,
    },
};

use iota_streams_core::{
    key_exchange::x25519,
    sponge::prp::PRP,
    wrapped_err,
    Errors::XPublicKeyGenerationFailure,
    WrappedError,
};

impl<'a, F: PRP, OS: io::OStream> X25519<&'a x25519::SecretKey, &'a x25519::PublicKey> for Context<F, OS> {
    fn x25519(&mut self, sk: &x25519::SecretKey, pk: &x25519::PublicKey) -> Result<&mut Self> {
        let shared = sk.diffie_hellman(pk);
        self.spongos.absorb_key(shared.as_bytes());
        Ok(self)
    }
}

impl<'a, F: PRP, OS: io::OStream> X25519<&'a x25519::PublicKey, ()> for Context<F, OS> {
    fn x25519(&mut self, pk: &x25519::PublicKey, _: ()) -> Result<&mut Self> {
        let ephemeral_ke_sk =
            x25519::SecretKey::generate().map_err(|e| wrapped_err(XPublicKeyGenerationFailure, WrappedError(e)))?;
        let ephemeral_ke_pk = ephemeral_ke_sk.public_key();
        self.absorb(&ephemeral_ke_pk)?.x25519(&ephemeral_ke_sk, pk)?.commit()
    }
}

impl<'a, F: PRP, N: ArrayLength<u8>, OS: io::OStream> X25519<&'a x25519::PublicKey, &'a NBytes<N>> for Context<F, OS> {
    fn x25519(&mut self, pk: &x25519::PublicKey, key: &NBytes<N>) -> Result<&mut Self> {
        self.x25519(pk, ())?.mask(key)
    }
}

impl<'a, F: PRP, OS: io::OStream> X25519<&'a x25519::PublicKey, &'a Key> for Context<F, OS> {
    fn x25519(&mut self, pk: &x25519::PublicKey, key: &Key) -> Result<&mut Self> {
        self.x25519(pk, ())?.mask(key)
    }
}
