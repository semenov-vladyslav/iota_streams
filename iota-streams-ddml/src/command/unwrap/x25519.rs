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
};

impl<'a, F: PRP, IS: io::IStream> X25519<&'a x25519::SecretKey, &'a x25519::PublicKey> for Context<F, IS> {
    fn x25519(&mut self, sk: &x25519::SecretKey, pk: &x25519::PublicKey) -> Result<&mut Self> {
        let shared = sk.diffie_hellman(pk);
        self.spongos.absorb_key(shared.as_bytes());
        Ok(self)
    }
}

impl<'a, F: PRP, N: ArrayLength<u8>, IS: io::IStream> X25519<&'a x25519::SecretKey, &'a mut NBytes<N>>
    for Context<F, IS>
{
    fn x25519(&mut self, sk: &x25519::SecretKey, key: &mut NBytes<N>) -> Result<&mut Self> {
        let mut ephemeral_ke_pk = x25519::PublicKey::from([0_u8; 32]);
        (*self)
            .absorb(&mut ephemeral_ke_pk)?
            .x25519(sk, &ephemeral_ke_pk)?
            .commit()?
            .mask(key)
    }
}

impl<'a, F: PRP, IS: io::IStream> X25519<&'a x25519::SecretKey, &'a mut Key> for Context<F, IS> {
    fn x25519(&mut self, sk: &x25519::SecretKey, key: &mut Key) -> Result<&mut Self> {
        let mut ephemeral_ke_pk = x25519::PublicKey::from([0_u8; 32]);
        (*self)
            .absorb(&mut ephemeral_ke_pk)?
            .x25519(sk, &ephemeral_ke_pk)?
            .commit()?
            .mask(key)
    }
}
