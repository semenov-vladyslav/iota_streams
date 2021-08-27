use iota_streams_core::Result;

use super::Context;
use crate::{
    command::X25519,
    types::{
        ArrayLength,
        Key,
        NBytes,
    },
};
use iota_streams_core::{
    key_exchange::x25519,
    sponge::KEY_SIZE,
};

impl<'a, F> X25519<&'a x25519::SecretKey, &'a x25519::PublicKey> for Context<F> {
    fn x25519(&mut self, _sk: &x25519::SecretKey, _pk: &x25519::PublicKey) -> Result<&mut Self> {
        // Only shared secret is absorbed externally.
        self.size += 0;
        Ok(self)
    }
}

impl<'a, F> X25519<&'a x25519::PublicKey, ()> for Context<F> {
    fn x25519(&mut self, _pk: &x25519::PublicKey, _: ()) -> Result<&mut Self> {
        self.size += x25519::PUBLIC_KEY_LENGTH;
        Ok(self)
    }
}

impl<'a, F, N: ArrayLength<u8>> X25519<&'a x25519::PublicKey, &'a NBytes<N>> for Context<F> {
    fn x25519(&mut self, pk: &x25519::PublicKey, _key: &NBytes<N>) -> Result<&mut Self> {
        self.x25519(pk, ())?.size += N::USIZE;
        Ok(self)
    }
}

impl<'a, F> X25519<&'a x25519::PublicKey, &'a Key> for Context<F> {
    fn x25519(&mut self, pk: &x25519::PublicKey, _key: &Key) -> Result<&mut Self> {
        self.x25519(pk, ())?.size += KEY_SIZE;
        Ok(self)
    }
}
