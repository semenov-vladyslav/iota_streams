//! Spongos-based pseudo-random number generator.

use crate::{
    prelude::{
        generic_array::{
            ArrayLength,
            GenericArray,
        },
        Vec,
    },
    sponge::{
        prp::PRP,
        spongos::Spongos,
        Key,
        Nonce,
    },
};

/// Generate cryptographically secure bytes.
/// Suitable for generating session and ephemeral keys.
pub fn random_bytes<N: ArrayLength<u8>>() -> GenericArray<u8, N> {
    let mut rnd = GenericArray::default();
    crypto::utils::rand::fill(rnd.as_mut_slice()).unwrap();
    rnd
}

/// Generate a random nonce.
pub fn random_nonce() -> Nonce {
    random_bytes()
}

/// Generate a random key.
pub fn random_key() -> Key {
    random_bytes()
}

/// Spongos-based pseudo-random number generator.
#[derive(Clone)]
pub struct Prng<G: PRP> {
    /// PRNG secret key.
    secret_key: Key,

    _phantom: core::marker::PhantomData<G>,
}

impl<G: PRP> Prng<G> {
    /// Create PRNG instance and init with a secret key.
    pub fn init(secret_key: Key) -> Self {
        Self {
            secret_key,
            _phantom: core::marker::PhantomData,
        }
    }

    fn key_from_seed(seed: impl AsRef<[u8]>) -> Key {
        let mut s = Spongos::<G>::init();
        s.absorb(seed);
        s.commit();
        let mut secret_key = Key::default();
        s.squeeze(&mut secret_key).unwrap();
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
        s.absorb_key(&self.secret_key[..]);
        for nonce in nonces {
            s.absorb(nonce);
        }
        s.commit();
        for rnd in rnds {
            s.squeeze(rnd).unwrap();
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

pub fn init<G: PRP>(secret_key: Key) -> Prng<G> {
    Prng::init(secret_key)
}

pub fn from_seed<G: PRP>(domain: &str, seed: &str) -> Prng<G> {
    let mut s = Spongos::<G>::init();
    s.absorb(seed.as_bytes());
    s.commit();
    s.absorb(domain.as_bytes());
    s.commit();
    Prng::init(s.squeeze_arr().unwrap())
}

pub fn dbg_init_str<G: PRP>(secret_key: &str) -> Prng<G> {
    from_seed("IOTA Streams dbg prng init", secret_key)
}

pub struct Rng<G: PRP> {
    prng: Prng<G>,
    nonce: Nonce,
}

impl<G: PRP> Rng<G> {
    pub fn new(prng: Prng<G>, nonce: Nonce) -> Self {
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
