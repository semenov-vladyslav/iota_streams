//! Spongos-based pseudo-random number generator.

use crate::{
    prelude::{
        generic_array::{
            typenum::{
                U16,
                U32,
            },
            ArrayLength,
            GenericArray,
        },
        Vec,
    },
    sponge::{
        prp::PRP,
        spongos::{
            self,
            Spongos,
        },
    },
};

/// Generate cryptographically secure bytes.
/// Suitable for generating session and ephemeral keys.
pub fn random_bytes<R, N: ArrayLength<u8>>(rng: &mut R) -> GenericArray<u8, N>
where
    R: rand::RngCore + rand::CryptoRng,
{
    let mut rnd = GenericArray::default();
    rng.fill_bytes(rnd.as_mut_slice());
    rnd
}

pub type Nonce = GenericArray<u8, U16>;

/// Generate a random nonce.
pub fn random_nonce() -> Nonce {
    random_bytes(&mut rng())
}

pub type Key = GenericArray<u8, U32>;

/// Generate a random key.
pub fn random_key() -> Key {
    random_bytes(&mut rng())
}

#[cfg(all(feature = "std", not(target_os = "espidf")))]
pub fn rng() -> rand::rngs::ThreadRng {
    rand::thread_rng()
}

// ESPIDF targets (ESP32 family) have std available through-ESP-IDF but
// pthread_atfork is not implemented, which is necessary to get the thread handle
// by rand::thread_rng(). Instead, we use a one-off StdRng instance seeded
// with `getrandom` (`esp_fill_random`). Given the coldness of this
// function (at least in streams-channels) in practice this approach has a
// similar security and performance as ThreadRng.
#[cfg(all(feature = "std", target_os = "espidf"))]
pub fn rng() -> rand::rngs::StdRng {
    <rand::rngs::StdRng as rand::SeedableRng>::from_entropy()
}

#[cfg(not(feature = "std"))]
pub fn rng() -> rand::rngs::StdRng {
    unimplemented!("No default global RNG present.");
}

/// Prng fixed key size.
pub type KeySize<F> = spongos::KeySize<F>;
pub type KeyType<F> = spongos::KeyType<F>;

/// Spongos-based pseudo-random number generator.
#[derive(Clone)]
pub struct Prng<G: PRP> {
    /// PRNG secret key.
    secret_key: KeyType<G>,

    _phantom: core::marker::PhantomData<G>,
}

impl<G: PRP> Prng<G> {
    /// Create PRNG instance and init with a secret key.
    pub fn init(secret_key: KeyType<G>) -> Self {
        Self {
            secret_key,
            _phantom: core::marker::PhantomData,
        }
    }

    fn key_from_seed(seed: impl AsRef<[u8]>) -> KeyType<G> {
        let mut s = Spongos::<G>::init();
        s.absorb(seed);
        s.commit();
        let mut secret_key = KeyType::<G>::default();
        s.squeeze(&mut secret_key);
        secret_key
    }

    /// Derive secret key from seed and init PRNG with it.
    pub fn init_with_seed(seed: impl AsRef<[u8]>) -> Self {
        Self::init(Self::key_from_seed(seed))
    }

    // TODO: PRNG randomness hierarchy via nonce: domain (seed, ed/x25519, session key, etc.), secret, counter.
    fn gen_with_spongos<'a>(&self, s: &mut Spongos<G>, nonces: &[&'a [u8]], rnds: &mut [&'a mut [u8]]) {
        // TODO: `dst` byte?
        // TODO: Reimplement PRNG with DDML?
        s.absorb(&self.secret_key[..]);
        for nonce in nonces {
            s.absorb(nonce);
        }
        s.commit();
        for rnd in rnds {
            s.squeeze(rnd);
        }
    }

    /// Generate randomness with a unique nonce for the current PRNG instance.
    pub fn gen(&self, nonce: impl AsRef<[u8]>, mut rnd: impl AsMut<[u8]>) {
        let mut s = Spongos::<G>::init();
        self.gen_with_spongos(&mut s, &[nonce.as_ref()], &mut [rnd.as_mut()]);
    }

    pub fn gen_arr<N: ArrayLength<u8>>(&self, nonce: impl AsRef<[u8]>) -> GenericArray<u8, N> {
        let mut rnd = GenericArray::default();
        self.gen(nonce, &mut rnd);
        rnd
    }

    /// Generate Tbits.
    pub fn gen_n(&self, nonce: impl AsRef<[u8]>, n: usize) -> Vec<u8> {
        let mut rnd = vec![0; n];
        self.gen(nonce, &mut rnd);
        rnd
    }
}

pub fn init<G: PRP>(secret_key: KeyType<G>) -> Prng<G> {
    Prng::init(secret_key)
}

pub fn from_seed<G: PRP>(domain: &str, seed: &str) -> Prng<G> {
    let mut s = Spongos::<G>::init();
    s.absorb(seed.as_bytes());
    s.commit();
    s.absorb(domain.as_bytes());
    s.commit();
    Prng::init(s.squeeze_arr())
}

pub fn dbg_init_str<G: PRP>(secret_key: &str) -> Prng<G> {
    from_seed("IOTA Streams dbg prng init", secret_key)
}

/// Rng fixed nonce size.
pub type NonceSize<F> = spongos::NonceSize<F>;
// pub type NonceType<F> = spongos::NonceType<F>;
pub type NonceType = Vec<u8>;

pub struct Rng<G: PRP> {
    prng: Prng<G>,
    nonce: NonceType,
}

impl<G: PRP> Rng<G> {
    pub fn new(prng: Prng<G>, nonce: NonceType) -> Self {
        Self { prng, nonce }
    }

    #[allow(clippy::assign_op_pattern)]
    fn inc(&mut self) -> bool {
        for i in self.nonce.iter_mut() {
            *i = *i + 1;
            if *i != 0 {
                return true;
            }
        }
        // self.nonce.push(0);
        false
    }
}

impl<G: PRP> rand::RngCore for Rng<G> {
    fn next_u32(&mut self) -> u32 {
        let mut v = [0_u8; 4];
        self.prng.gen(&self.nonce[..], &mut v);
        self.inc();
        u32::from_le_bytes(v)
    }
    fn next_u64(&mut self) -> u64 {
        let mut v = [0_u8; 8];
        self.prng.gen(&self.nonce[..], &mut v);
        self.inc();
        u64::from_le_bytes(v)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.prng.gen(&self.nonce[..], dest);
        self.inc();
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl<G: PRP> rand::CryptoRng for Rng<G> {}
