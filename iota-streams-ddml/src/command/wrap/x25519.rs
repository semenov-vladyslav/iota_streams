#[cfg(not(feature = "std"))]
use iota_streams_core::{
    err,
    Errors::NoStdRngMissing,
};

#[cfg(feature = "std")]
use iota_streams_core::prng::rng;
use iota_streams_core::Result;

use super::Context;
#[cfg(feature = "std")]
use crate::command::{
    Absorb,
    Commit,
    Mask,
};
use crate::{
    command::X25519,
    io,
    types::{
        ArrayLength,
        NBytes,
    },
};

use iota_streams_core::sponge::prp::PRP;
use iota_streams_core_edsig::key_exchange::x25519;

impl<'a, F: PRP, OS: io::OStream> X25519<&'a x25519::StaticSecret, &'a x25519::PublicKey> for Context<F, OS> {
    fn x25519(&mut self, sk: &x25519::StaticSecret, pk: &x25519::PublicKey) -> Result<&mut Self> {
        let shared = sk.diffie_hellman(pk);
        self.spongos.absorb(shared.as_bytes());
        Ok(self)
    }
}

impl<'a, F: PRP, OS: io::OStream> X25519<x25519::EphemeralSecret, &'a x25519::PublicKey> for Context<F, OS> {
    fn x25519(&mut self, sk: x25519::EphemeralSecret, pk: &x25519::PublicKey) -> Result<&mut Self> {
        let shared = sk.diffie_hellman(pk);
        self.spongos.absorb(shared.as_bytes());
        Ok(self)
    }
}

#[cfg(feature = "std")]
impl<'a, F: PRP, N: ArrayLength<u8>, OS: io::OStream> X25519<&'a x25519::PublicKey, &'a NBytes<N>> for Context<F, OS> {
    fn x25519(&mut self, pk: &x25519::PublicKey, key: &NBytes<N>) -> Result<&mut Self> {
        let ephemeral_ke_sk = x25519::EphemeralSecret::new(&mut rng());
        let ephemeral_ke_pk = x25519::PublicKey::from(&ephemeral_ke_sk);
        self.absorb(&ephemeral_ke_pk)?
            .x25519(ephemeral_ke_sk, pk)?
            .commit()?
            .mask(key)
    }
}

#[cfg(not(feature = "std"))]
impl<'a, F: PRP, N: ArrayLength<u8>, OS: io::OStream> X25519<&'a x25519::PublicKey, &'a NBytes<N>> for Context<F, OS> {
    fn x25519(&mut self, _pk: &x25519::PublicKey, _key: &NBytes<N>) -> Result<&mut Self> {
        // TODO: no_std make default rng
        err!(NoStdRngMissing)
    }
}
