#![allow(clippy::many_single_char_names)]
use super::{
    prp::PRP,
    spongos::*,
};
use crate::{
    err,
    prelude::{
        generic_array::GenericArray,
        typenum::{
            self,
            Unsigned,
        },
        Vec,
    },
};

#[derive(Default, Copy, Clone, PartialEq, Eq)]
pub struct TestF10x5(pub [u8; 15]);

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct TestF64x32(pub [u8; 96]);

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct TestF256x128(pub [u8; 384]);

impl Default for TestF64x32 {
    fn default() -> Self {
        Self([0_u8; 96])
    }
}

impl Default for TestF256x128 {
    fn default() -> Self {
        Self([0_u8; 384])
    }
}

fn transform(s: &mut [u8]) {
    let i = 1_u8;
    s[0] += 1;
    for x in s {
        *x = *x ^ i;
    }
}

impl PRP for TestF10x5 {
    type RateSize = typenum::U10;

    type CapacitySize = typenum::U5;

    fn transform(&mut self) {
        transform(&mut self.0)
    }

    fn outer(&self) -> &GenericArray<u8, Self::RateSize> {
        unsafe { &*(self.0.as_ptr() as *const GenericArray<u8, Self::RateSize>) }
    }

    fn outer_mut(&mut self) -> &mut GenericArray<u8, Self::RateSize> {
        unsafe { &mut *(self.0.as_mut_ptr() as *mut GenericArray<u8, Self::RateSize>) }
    }

    fn inner(&self) -> &GenericArray<u8, Self::CapacitySize> {
        unsafe { &*(self.0.as_ptr().add(10) as *const GenericArray<u8, Self::CapacitySize>) }
    }

    fn from_inner(inner: &GenericArray<u8, Self::CapacitySize>) -> Self {
        let mut state = [0_u8; 15];
        let i = unsafe { &mut *(state.as_mut_ptr().add(10) as *mut GenericArray<u8, Self::CapacitySize>) };
        *i = *inner;
        Self(state)
    }
}

impl PRP for TestF64x32 {
    type RateSize = typenum::U64;

    type CapacitySize = typenum::U32;

    fn transform(&mut self) {
        transform(&mut self.0)
    }

    fn outer(&self) -> &GenericArray<u8, Self::RateSize> {
        unsafe { &*(self.0.as_ptr() as *const GenericArray<u8, Self::RateSize>) }
    }

    fn outer_mut(&mut self) -> &mut GenericArray<u8, Self::RateSize> {
        unsafe { &mut *(self.0.as_mut_ptr() as *mut GenericArray<u8, Self::RateSize>) }
    }

    fn inner(&self) -> &GenericArray<u8, Self::CapacitySize> {
        unsafe { &*(self.0.as_ptr().add(64) as *const GenericArray<u8, Self::CapacitySize>) }
    }

    fn from_inner(inner: &GenericArray<u8, Self::CapacitySize>) -> Self {
        let mut state = [0_u8; 96];
        let i = unsafe { &mut *(state.as_mut_ptr().add(64) as *mut GenericArray<u8, Self::CapacitySize>) };
        *i = *inner;
        Self(state)
    }
}

impl PRP for TestF256x128 {
    type RateSize = typenum::U256;

    type CapacitySize = typenum::U128;

    fn transform(&mut self) {
        transform(&mut self.0)
    }

    fn outer(&self) -> &GenericArray<u8, Self::RateSize> {
        unsafe { &*(self.0.as_ptr() as *const GenericArray<u8, Self::RateSize>) }
    }

    fn outer_mut(&mut self) -> &mut GenericArray<u8, Self::RateSize> {
        unsafe { &mut *(self.0.as_mut_ptr() as *mut GenericArray<u8, Self::RateSize>) }
    }

    fn inner(&self) -> &GenericArray<u8, Self::CapacitySize> {
        unsafe { &*(self.0.as_ptr().add(256) as *const GenericArray<u8, Self::CapacitySize>) }
    }

    fn from_inner(inner: &GenericArray<u8, Self::CapacitySize>) -> Self {
        let mut state = [0_u8; 384];
        let i = unsafe { &mut *(state.as_mut_ptr().add(256) as *mut GenericArray<u8, Self::CapacitySize>) };
        *i = *inner;
        Self(state)
    }
}

fn should_fail(r: crate::Result<()>) -> crate::Result<()> {
    match r {
        Ok(()) => err(crate::Errors::TestShouldFail),
        Err(_) => Ok(()),
    }
}

fn bytes_spongosn<F: PRP>(n: usize) -> crate::Result<()> {
    let mut rng = Spongos::<F>::init();
    rng.absorb(&vec![0; 10]);
    rng.commit();
    let k = rng.squeeze_n(n)?;
    let p = rng.squeeze_n(n)?;
    let x = rng.squeeze_n(n)?;
    let y: Vec<u8>;
    let mut z: Vec<u8>;
    let t: Vec<u8>;
    let u: Vec<u8>;
    let t2: Vec<u8>;
    let t3: Vec<u8>;

    {
        let mut s = Spongos::<F>::init();
        s.absorb_key(&k);
        s.absorb(&p);
        s.commit();
        y = s.encrypt_n(&x)?;
        s.commit();
        t = s.squeeze_n(n)?;
        t2 = s.squeeze_n(n)?;
        t3 = s.squeeze_n(n)?;
    }

    {
        let mut s = Spongos::<F>::init();
        s.absorb_key(&k);
        s.absorb(&p);
        s.commit();
        z = y;
        s.decrypt_mut(&mut z)?;
        s.commit();
        u = s.squeeze_n(n)?;
        assert!(s.squeeze_eq(&t2)?);
        assert!(s.squeeze_eq(&t3)?);
    }

    assert!(x == z, "{}: x != D(E(x))", n);
    assert!(t == u, "{}: MAC(x) != MAC(D(E(x)))", n);
    Ok(())
}

fn slice_spongosn<F: PRP>(n: usize) -> crate::Result<()> {
    let mut k = vec![0_u8; n];
    let mut p = vec![0_u8; n];
    let mut x = vec![0_u8; n];
    let mut y = vec![0_u8; n];
    let mut z = vec![0_u8; n];
    let mut t = vec![0_u8; n];
    let mut u = vec![0_u8; n];
    let mut t23 = vec![0_u8; n + n];

    let mut s: Spongos<F>;
    {
        s = Spongos::init();
        s.absorb_key(&k[..]);
        s.commit();
        s.squeeze(&mut k[..])?;
        s.squeeze(&mut p[..])?;
        s.squeeze(&mut x[..])?;
    }

    {
        s = Spongos::init();
        s.absorb_key(&k[..]);
        s.absorb(&p[..]);
        s.commit();
        s.encrypt(&x[..], &mut y[..])?;
        s.commit();
        s.squeeze(&mut t[..])?;
        s.squeeze(&mut t23[..n])?;
        s.squeeze(&mut t23[n..])?;
    }

    {
        s = Spongos::init();
        s.absorb_key(&k[..]);
        s.absorb(&p[..]);
        s.commit();
        s.decrypt(&y[..], &mut z[..])?;
        s.commit();
        s.squeeze(&mut u[..])?;
        assert!(s.squeeze_eq(&t23[..n])?);
        assert!(s.squeeze_eq(&t23[n..])?);
    }

    assert!(x == z, "{}: x != D(E(x))", n);
    assert!(t == u, "{}: MAC(x) != MAC(D(E(x)))", n);
    Ok(())
}

pub fn bytes_with_size_boundary_cases<F: PRP>() -> crate::Result<()> {
    let rate = F::RateSize::USIZE;
    for i in 1..100 {
        bytes_spongosn::<F>(i)?;
    }
    bytes_spongosn::<F>(rate / 2 - 1)?;
    bytes_spongosn::<F>(rate / 2)?;
    bytes_spongosn::<F>(rate / 2 + 1)?;
    bytes_spongosn::<F>(rate - 1)?;
    bytes_spongosn::<F>(rate)?;
    bytes_spongosn::<F>(rate + 1)?;
    bytes_spongosn::<F>(rate * 2 - 1)?;
    bytes_spongosn::<F>(rate * 2)?;
    bytes_spongosn::<F>(rate * 2 + 1)?;
    bytes_spongosn::<F>(rate * 5)?;
    Ok(())
}

#[test]
fn test_bytes_with_size_boundary_cases() -> crate::Result<()> {
    bytes_with_size_boundary_cases::<TestF10x5>()?;
    bytes_with_size_boundary_cases::<TestF64x32>()?;
    bytes_with_size_boundary_cases::<TestF256x128>()?;
    Ok(())
}

pub fn slices_with_size_boundary_cases<F: PRP>() -> crate::Result<()> {
    let rate = F::RateSize::USIZE;
    for i in 1..100 {
        slice_spongosn::<F>(i)?;
    }
    slice_spongosn::<F>(rate / 2 - 1)?;
    slice_spongosn::<F>(rate / 2)?;
    slice_spongosn::<F>(rate / 2 + 1)?;
    slice_spongosn::<F>(rate - 1)?;
    slice_spongosn::<F>(rate)?;
    slice_spongosn::<F>(rate + 1)?;
    slice_spongosn::<F>(rate * 2 - 1)?;
    slice_spongosn::<F>(rate * 2)?;
    slice_spongosn::<F>(rate * 2 + 1)?;
    slice_spongosn::<F>(rate * 5)?;
    Ok(())
}

#[test]
fn test_slices_with_size_boundary_cases() -> crate::Result<()> {
    slices_with_size_boundary_cases::<TestF10x5>()?;
    slices_with_size_boundary_cases::<TestF64x32>()?;
    slices_with_size_boundary_cases::<TestF256x128>()?;
    Ok(())
}

pub fn encrypt_decrypt_n<F: PRP>(n: usize) -> crate::Result<()> {
    let rate = F::RateSize::USIZE;
    let mut s = Spongos::<F>::init();
    s.absorb_key(&vec![1; 32]);
    s.commit();

    let x = s.clone().squeeze_n(n)?;
    {
        let mut s2 = s.clone();
        let mut s3 = s.clone();
        let mut s4 = s.clone();

        let ex = s.encrypt_n(&x)?;
        s.commit();
        let tag = s.squeeze_n(rate)?;

        let dex = s2.decrypt_n(&ex)?;
        assert_eq!(x, dex);
        s2.commit();
        assert_eq!(tag, s2.squeeze_n(rate)?);

        let mut x2 = x.clone();
        s3.encrypt_mut(&mut x2)?;
        assert_eq!(ex, x2);
        s3.commit();
        assert_eq!(tag, s3.squeeze_n(rate)?);

        s4.decrypt_mut(&mut x2)?;
        assert_eq!(x, x2);
        s4.commit();
        assert_eq!(tag, s4.squeeze_n(rate)?);
    }
    Ok(())
}

#[test]
fn test_encrypt_decrypt() -> crate::Result<()> {
    const NS: [usize; 9] = [0, 1, 5, 9, 10, 11, 255, 256, 257];
    for n in NS {
        encrypt_decrypt_n::<TestF10x5>(n)?;
        encrypt_decrypt_n::<TestF64x32>(n)?;
        encrypt_decrypt_n::<TestF256x128>(n)?;
    }
    Ok(())
}

pub fn inner<F: PRP>() {
    let s = Spongos::<F>::init();

    let mut s0 = s.clone();
    s0.commit();
    let inner0 = s0.get_inner();

    let mut s1 = s.clone();
    s1.absorb(&[0]);
    s1.commit();
    let inner1 = s1.get_inner();

    let mut s2 = s.clone();
    s2.absorb(&[0, 0]);
    s2.commit();
    let inner2 = s2.get_inner();

    assert!(inner0 != inner1);
    // NB: Two different inputs [0] and [0, 0] absorbed result
    // in the same (inner) state. This is intentional,
    // the length must precede the data.
    assert!(inner1 == inner2);
}

#[test]
fn test_inner() {
    inner::<TestF10x5>();
    inner::<TestF64x32>();
    inner::<TestF256x128>();
}

fn join_key_commit_encrypt<F: PRP>() -> crate::Result<()> {
    let mut joinee = Spongos::<F>::init();
    joinee.absorb_key(&[1]);

    let mut s = Spongos::<F>::init();
    s.join(&mut joinee);
    s.commit();
    s.encrypt_mut(&mut [2])
}

#[test]
fn test_join_key_commit_encrypt() -> crate::Result<()> {
    join_key_commit_encrypt::<TestF10x5>()?;
    join_key_commit_encrypt::<TestF64x32>()?;
    join_key_commit_encrypt::<TestF256x128>()?;
    Ok(())
}

fn join_key_encrypt<F: PRP>() -> crate::Result<()> {
    let mut joinee = Spongos::<F>::init();
    joinee.absorb_key(&[1]);

    let mut s = Spongos::<F>::init();
    s.join(&mut joinee);
    s.encrypt_mut(&mut [2])
}

#[test]
fn test_join_key_encrypt() -> crate::Result<()> {
    should_fail(join_key_encrypt::<TestF10x5>())
}

fn join_no_key_encrypt<F: PRP>() -> crate::Result<()> {
    let mut s0 = Spongos::<F>::init();
    s0.absorb(&[1]);
    s0.commit();

    let mut s = Spongos::<F>::init();
    s.join(&mut s0);
    s.encrypt_mut(&mut [2])
}

#[test]
fn test_join_no_key_encrypt() -> crate::Result<()> {
    should_fail(join_no_key_encrypt::<TestF10x5>())
}

fn encrypt_no_key<F: PRP>() -> crate::Result<()> {
    let mut s = Spongos::<F>::init();
    s.absorb(&[0]);
    s.encrypt_mut(&mut [2])
}

#[test]
fn test_encrypt_no_key() -> crate::Result<()> {
    should_fail(encrypt_no_key::<TestF10x5>())
}

fn decrypt_no_key<F: PRP>() -> crate::Result<()> {
    let mut s = Spongos::<F>::init();
    s.absorb(&[0]);
    s.decrypt_mut(&mut [2])
}

#[test]
fn test_decrypt_no_key() -> crate::Result<()> {
    should_fail(decrypt_no_key::<TestF10x5>())
}

fn squeeze_tag_no_key<F: PRP>() -> crate::Result<()> {
    let mut s = Spongos::<F>::init();
    s.absorb(&[0]);
    s.commit();
    s.squeeze_tag(&mut [2])
}

#[test]
fn test_squeeze_tag_no_key() -> crate::Result<()> {
    should_fail(squeeze_tag_no_key::<TestF10x5>())
}

fn squeeze_tag_eq_no_key<F: PRP>() -> crate::Result<bool> {
    let mut s = Spongos::<F>::init();
    s.absorb(&[0]);
    s.commit();
    s.squeeze_tag_eq(&[2])
}

#[test]
fn test_squeeze_tag_eq_no_key() -> crate::Result<()> {
    should_fail(squeeze_tag_eq_no_key::<TestF10x5>().map(|_| ()))
}

#[cfg(feature = "keccak")]
mod test_keccak {
    use super::*;
    use crate::sponge::prp::keccak::KeccakF1600;

    #[test]
    fn bytes_with_size_boundary_cases_keccak_byte() -> crate::Result<()> {
        bytes_with_size_boundary_cases::<KeccakF1600>()
    }

    #[test]
    fn slices_with_size_boundary_cases_keccak_byte() -> crate::Result<()> {
        slices_with_size_boundary_cases::<KeccakF1600>()
    }

    #[test]
    fn encrypt_decrypt_keccak_byte() -> crate::Result<()> {
        let rate = <KeccakF1600 as PRP>::RateSize::USIZE;
        encrypt_decrypt_n::<KeccakF1600>(27)?;
        encrypt_decrypt_n::<KeccakF1600>(rate)?;
        encrypt_decrypt_n::<KeccakF1600>(rate - 28)?;
        encrypt_decrypt_n::<KeccakF1600>(rate + 28)?;
        encrypt_decrypt_n::<KeccakF1600>(2 * rate)?;
        Ok(())
    }
}
