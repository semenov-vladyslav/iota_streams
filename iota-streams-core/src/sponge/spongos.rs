use core::{
    fmt,
    ops::Mul,
};

use super::prp::{
    Inner,
    PRP,
};
use crate::{
    prelude::{
        digest::Digest,
        generic_array::{
            typenum::{
                Unsigned,
                U2,
            },
            ArrayLength,
            GenericArray,
        },
        Vec,
    },
    try_or,
    Errors::{
        LengthMismatch,
        SpongosInputNotCommitted,
        SpongosKeyNotCommitted,
    },
    Result,
};

fn xor(s: &mut [u8], x: &[u8]) {
    for (si, xi) in s.iter_mut().zip(x.iter()) {
        *si ^= *xi;
    }
}

fn encrypt_xor(s: &mut [u8], x: &[u8], y: &mut [u8]) {
    for (si, (xi, yi)) in s.iter_mut().zip(x.iter().zip(y.iter_mut())) {
        *yi = *si ^ *xi;
        *si = *yi;
    }
}

fn decrypt_xor(s: &mut [u8], y: &[u8], x: &mut [u8]) {
    for (si, (yi, xi)) in s.iter_mut().zip(y.iter().zip(x.iter_mut())) {
        *xi = *si ^ *yi;
        *si = *yi;
    }
}

fn encrypt_xor_mut(s: &mut [u8], x: &mut [u8]) {
    for (si, xi) in s.iter_mut().zip(x.iter_mut()) {
        *xi ^= *si;
        *si = *xi;
    }
}

fn decrypt_xor_mut(s: &mut [u8], y: &mut [u8]) {
    for (si, yi) in s.iter_mut().zip(y.iter_mut()) {
        let t = *yi;
        *yi ^= *si;
        *si = t;
    }
}

fn copy(s: &[u8], y: &mut [u8]) {
    for (si, yi) in s.iter().zip(y.iter_mut()) {
        *yi = *si;
    }
}

fn equals(s: &[u8], x: &[u8]) -> bool {
    let mut eq = true;
    for (si, xi) in s.iter().zip(x.iter()) {
        eq = (*si == *xi) && eq;
    }
    eq
}

/// Current operation is processing input: absorb or mask or join.
const PROCESSING_INPUT: u8 = 1_u8;
/// Current operation is producing output: squeeze or mask.
const PRODUCING_OUTPUT: u8 = 2_u8;
/// Key is being absorbed, it must be committed before keyed
/// operations mask and tag.
const KEY_ABSORB: u8 = 4_u8;
/// Key must be committed for keyed operations: mask and tag.
const KEY_COMMITTED: u8 = KEY_ABSORB << 1;

#[derive(Clone)]
pub struct Spongos<F> {
    /// Spongos transform together with its internal state.
    s: F,

    /// Flags provide run-time checks against forbidden operations
    /// that are allowed at compile time.
    flags: u8,

    /// Current position (offset in bytes) within the outer state.
    pos: usize,
}

impl<F: PRP> Spongos<F> {
    /// Create a Spongos object, initialize state with zero bytes.
    pub fn init() -> Self {
        Self::init_with_state(F::default())
    }

    /// Init spongos to work in a specific domain.
    /// Domain can include application name and/or
    /// description of the spongos operations to follow.
    pub fn init_with_domain(domain: &[u8]) -> Self {
        // TODO: implement Spongos::init_with_domain more efficiently.
        let mut s = Self::init();
        s.absorb(domain);
        s.commit();
        s
    }

    pub fn flags(&self) -> u8 {
        self.flags
    }

    /// Create a Spongos object with an explicit state.
    pub fn init_with_state(s: F) -> Self {
        Self { s, flags: 0, pos: 0 }
    }

    fn outer_min_mut(&mut self, n: usize) -> &mut [u8] {
        let m = core::cmp::min(self.pos + n, F::RateSize::USIZE);
        &mut self.s.outer_mut()[self.pos..m]
    }

    /// Update Spongos after processing the current piece of data of `n` bytes.
    fn update(&mut self, n: usize) {
        self.pos += n;
        if F::RateSize::USIZE == self.pos {
            self.commit();
        }
    }

    /// Absorb a byte slice into Spongos object.
    fn do_absorb(&mut self, xr: impl AsRef<[u8]>) {
        let mut x = xr.as_ref();
        while !x.is_empty() {
            let s = self.outer_min_mut(x.len());
            let n = s.len();
            xor(s, &x[..n]);
            x = &x[n..];
            self.update(n);
        }
    }

    /// Absorb public/plain data.
    pub fn absorb(&mut self, xr: impl AsRef<[u8]>) {
        // No restriction on absorbing plain data,
        // it can be done after any other operation.
        self.flags |= PROCESSING_INPUT;
        self.do_absorb(xr)
    }

    /// Absorb secret key.
    pub fn absorb_key(&mut self, xr: impl AsRef<[u8]>) {
        // No restriction on absorbing secret keys,
        // it can be done after any other operation.
        self.flags |= PROCESSING_INPUT | KEY_ABSORB;
        self.do_absorb(xr)
    }

    /// Squeeze a byte slice from Spongos object.
    fn squeeze_unchecked(&mut self, mut yr: impl AsMut<[u8]>) {
        let mut y = yr.as_mut();
        while !y.is_empty() {
            let s = self.outer_min_mut(y.len());
            let n = s.len();
            copy(s, &mut y[..n]);
            y = &mut y[n..];
            self.update(n);
        }
    }

    /// Squeeze a byte slice from Spongos object and compare.
    fn squeeze_eq_unchecked(&mut self, yr: impl AsRef<[u8]>) -> bool {
        let mut y = yr.as_ref();
        let mut eq = true;
        while !y.is_empty() {
            let s = self.outer_min_mut(y.len());
            let n = s.len();
            eq = equals(s, &y[..n]) && eq;
            y = &y[n..];
            self.update(n);
        }
        eq
    }

    /// Squeeze hash from Spongos object.
    pub fn squeeze(&mut self, yr: impl AsMut<[u8]>) -> Result<()> {
        // Can't squeeze hash after absorbing data without committing it.
        try_or!(0 == self.flags & PROCESSING_INPUT, SpongosInputNotCommitted)?;
        self.flags |= PRODUCING_OUTPUT;
        self.squeeze_unchecked(yr);
        Ok(())
    }

    /// Squeeze and compare hash.
    pub fn squeeze_eq(&mut self, yr: impl AsRef<[u8]>) -> Result<bool> {
        // Can't squeeze hash after absorbing data without committing it.
        try_or!(0 == self.flags & PROCESSING_INPUT, SpongosInputNotCommitted)?;
        self.flags |= PRODUCING_OUTPUT;
        Ok(self.squeeze_eq_unchecked(yr))
    }

    /// Squeeze tag from Spongos object.
    pub fn squeeze_tag(&mut self, yr: impl AsMut<[u8]>) -> Result<()> {
        // Can't squeeze tag after absorbing data without committing it.
        try_or!(0 == self.flags & PROCESSING_INPUT, SpongosInputNotCommitted)?;
        // Can't squeeze tag without having a key committed.
        try_or!(0 != self.flags & KEY_COMMITTED, SpongosKeyNotCommitted)?;
        self.flags |= PRODUCING_OUTPUT;
        self.squeeze_unchecked(yr);
        Ok(())
    }

    /// Squeeze and compare tag.
    pub fn squeeze_tag_eq(&mut self, yr: impl AsRef<[u8]>) -> Result<bool> {
        // Can't squeeze tag after absorbing data without committing it.
        try_or!(0 == self.flags & PROCESSING_INPUT, SpongosInputNotCommitted)?;
        // Can't squeeze tag without having a key committed.
        try_or!(0 != self.flags & KEY_COMMITTED, SpongosKeyNotCommitted)?;
        self.flags |= PRODUCING_OUTPUT;
        Ok(self.squeeze_eq_unchecked(yr))
    }

    /// Squeeze array, length inferred from output type.
    pub fn squeeze_arr<N: ArrayLength<u8>>(&mut self) -> Result<GenericArray<u8, N>> {
        let mut y = GenericArray::default();
        self.squeeze(&mut y)?;
        Ok(y)
    }

    /// Squeeze vector, length is known at runtime.
    pub fn squeeze_n(&mut self, n: usize) -> Result<Vec<u8>> {
        let mut v = vec![0; n];
        self.squeeze(&mut v)?;
        Ok(v)
    }

    /// Encrypt a byte slice with Spongos object.
    /// Input and output slices must be non-overlapping.
    fn encrypt_unchecked(&mut self, xr: impl AsRef<[u8]>, mut yr: impl AsMut<[u8]>) -> Result<()> {
        let mut x = xr.as_ref();
        let mut y = yr.as_mut();
        try_or!(x.len() == y.len(), LengthMismatch(x.len(), y.len()))?;
        while !x.is_empty() {
            let s = self.outer_min_mut(x.len());
            let n = s.len();
            encrypt_xor(s, &x[..n], &mut y[..n]);
            x = &x[n..];
            y = &mut y[n..];
            self.update(n);
        }
        Ok(())
    }

    /// Encrypt in-place a byte slice with Spongos object.
    fn encrypt_mut_unchecked(&mut self, mut xyr: impl AsMut<[u8]>) {
        let mut xy = xyr.as_mut();
        while !xy.is_empty() {
            let s = self.outer_min_mut(xy.len());
            let n = s.len();
            encrypt_xor_mut(s, &mut xy[..n]);
            xy = &mut xy[n..];
            self.update(n);
        }
    }

    /// Encrypt plain text.
    /// Input and output slices must be non-overlapping.
    pub fn encrypt(&mut self, xr: impl AsRef<[u8]>, yr: impl AsMut<[u8]>) -> Result<()> {
        // Can't encrypt data without having a key committed.
        try_or!(0 != self.flags & KEY_COMMITTED, SpongosKeyNotCommitted)?;
        self.flags |= PROCESSING_INPUT | PRODUCING_OUTPUT;
        self.encrypt_unchecked(xr, yr)
    }

    /// Encrypt in-place a byte slice with Spongos object.
    pub fn encrypt_mut(&mut self, xyr: impl AsMut<[u8]>) -> Result<()> {
        // Can't encrypt data without having a key committed.
        try_or!(0 != self.flags & KEY_COMMITTED, SpongosKeyNotCommitted)?;
        self.flags |= PROCESSING_INPUT | PRODUCING_OUTPUT;
        self.encrypt_mut_unchecked(xyr);
        Ok(())
    }

    /// Encrypt plaintext into fixed-length array.
    pub fn encrypt_arr<N: ArrayLength<u8>>(&mut self, x: &GenericArray<u8, N>) -> Result<GenericArray<u8, N>> {
        let mut y = GenericArray::default();
        self.encrypt(x, &mut y)?;
        Ok(y)
    }

    /// Encrypt plaintext into vector.
    pub fn encrypt_n(&mut self, x: impl AsRef<[u8]>) -> Result<Vec<u8>> {
        let mut y = vec![0; x.as_ref().len()];
        self.encrypt(x, &mut y)?;
        Ok(y)
    }

    /// Try to encrypt 1 byte, it's allowed to encrypt a zero byte without key.
    pub fn encrypt1z(&mut self, x: u8) -> Result<u8> {
        let has_key_committed = 0 != self.flags & KEY_COMMITTED;
        try_or!(0 == x || has_key_committed, SpongosKeyNotCommitted)?;
        self.flags |= PROCESSING_INPUT | PRODUCING_OUTPUT;

        let mut xy = [x];
        let s = self.outer_min_mut(1);
        encrypt_xor_mut(s, &mut xy);
        self.update(1);
        let y = xy[0];

        Ok(y)
    }

    /// Decrypt a byte slice with Spongos object.
    /// Input and output slices must be non-overlapping.
    fn decrypt_unchecked(&mut self, yr: impl AsRef<[u8]>, mut xr: impl AsMut<[u8]>) -> Result<()> {
        let mut y = yr.as_ref();
        let mut x = xr.as_mut();
        try_or!(x.len() == y.len(), LengthMismatch(x.len(), y.len()))?;
        while !x.is_empty() {
            let s = self.outer_min_mut(y.len());
            let n = s.len();
            decrypt_xor(s, &y[..n], &mut x[..n]);
            y = &y[n..];
            x = &mut x[n..];
            self.update(n);
        }
        Ok(())
    }

    /// Decrypt in-place a byte slice with Spongos object.
    fn decrypt_mut_unchecked(&mut self, mut yxr: impl AsMut<[u8]>) {
        let mut yx = yxr.as_mut();
        while !yx.is_empty() {
            let s = self.outer_min_mut(yx.len());
            let n = s.len();
            decrypt_xor_mut(s, &mut yx[..n]);
            yx = &mut yx[n..];
            self.update(n);
        }
    }

    /// Decrypt cipher text.
    /// Input and output slices must be non-overlapping.
    pub fn decrypt(&mut self, yr: impl AsRef<[u8]>, xr: impl AsMut<[u8]>) -> Result<()> {
        // Can't decrypt data without having a key committed.
        try_or!(0 != self.flags & KEY_COMMITTED, SpongosKeyNotCommitted)?;
        self.flags |= PROCESSING_INPUT | PRODUCING_OUTPUT;
        self.decrypt_unchecked(yr, xr)
    }

    /// Decrypt cipher text in-place.
    pub fn decrypt_mut(&mut self, yxr: impl AsMut<[u8]>) -> Result<()> {
        // Can't decrypt data without having a key committed.
        try_or!(0 != self.flags & KEY_COMMITTED, SpongosKeyNotCommitted)?;
        self.flags |= PROCESSING_INPUT | PRODUCING_OUTPUT;
        self.decrypt_mut_unchecked(yxr);
        Ok(())
    }

    /// Decrypt cipher text into fixed-length array.
    pub fn decrypt_arr<N: ArrayLength<u8>>(&mut self, y: &GenericArray<u8, N>) -> Result<GenericArray<u8, N>> {
        let mut x = GenericArray::default();
        self.decrypt(y, &mut x)?;
        Ok(x)
    }

    /// Decrypt cipher text into vector.
    pub fn decrypt_n(&mut self, y: impl AsRef<[u8]>) -> Result<Vec<u8>> {
        let mut x = vec![0; y.as_ref().len()];
        self.decrypt(y, &mut x)?;
        Ok(x)
    }

    /// Try to decrypt 1 byte, it's allowed to decrypt a zero byte without key.
    pub fn decrypt1z(&mut self, y: u8) -> Result<u8> {
        let had_key_committed = 0 != self.flags & KEY_COMMITTED;
        self.flags |= PROCESSING_INPUT | PRODUCING_OUTPUT;

        let mut yx = [y];
        let s = self.outer_min_mut(1);
        decrypt_xor_mut(s, &mut yx);
        self.update(1);
        let x = yx[0];

        try_or!(0 == x || had_key_committed, SpongosKeyNotCommitted)?;
        Ok(x)
    }

    /// Force transform even if for incomplete (but non-empty!) outer state.
    /// Commit with empty outer state has no effect.
    fn do_commit(&mut self) {
        if self.pos != 0 {
            for o in &mut self.s.outer_mut()[self.pos..] {
                *o = 0
            }
            self.s.transform();
            self.pos = 0;
        }
    }

    /// Force transform even if for incomplete (but non-empty!) outer state.
    /// Commit with empty outer state has no effect.
    pub fn commit(&mut self) {
        // Do we have a key absorbed?
        let key_absorb = self.flags & KEY_ABSORB;
        // If so, let's commit it.
        let key_committed = key_absorb << 1;
        // It'll stay committed forever.
        self.flags |= key_committed;
        // We no longer process any input or produce any output.
        self.flags &= !(PROCESSING_INPUT | PRODUCING_OUTPUT | KEY_ABSORB);
        self.do_commit()
    }

    /// Check whether Spongos state is committed.
    pub fn is_committed(&self) -> bool {
        0 == self.pos
    }

    /// Check whether Spongos state has key committed.
    pub fn has_key(&self) -> bool {
        0 != self.flags & KEY_COMMITTED
    }

    /// Join two Spongos objects.
    /// Joiner -- self -- object absorbs data squeezed from joinee.
    fn do_join(&mut self, joinee: &mut Self) {
        joinee.commit();
        // Clear outer state, this is equivalent to having joinee initialized
        // from inner state as join must work in the same way for full and
        // trimmed Spongos.
        for o in joinee.s.outer_mut() {
            *o = 0;
        }
        joinee.s.transform();
        let mut x = GenericArray::<u8, F::CapacitySize>::default();
        joinee.squeeze(x.as_mut()).unwrap();
        self.absorb(x.as_ref());
    }

    /// Join two Spongos objects.
    /// Joiner -- self -- object absorbs data squeezed from joinee.
    pub fn join(&mut self, joinee: &mut Self) {
        self.do_join(joinee);
        // Joinee has key committed?
        let key_committed = joinee.flags & KEY_COMMITTED;
        // If so, after the join we essentially absorbed a key.
        let key_absorb = key_committed >> 1;
        // So need to update flags. Don't forget to commit before mask and tag.
        self.flags |= key_absorb;
    }

    /// Fork Spongos object into another.
    /// Essentially this just creates a clone of self.
    pub fn fork_at(&self, fork: &mut Self) {
        fork.clone_from(self);
    }

    /// Fork Spongos object into a new one.
    /// Essentially this just creates a clone of self.
    pub fn fork(&self) -> Self {
        self.clone()
    }

    /// Only `inner` part of the state may be serialized.
    /// State should be committed.
    pub fn to_inner(mut self) -> Inner<F> {
        self.commit();
        Inner::new(self.s.inner().clone(), self.flags)
    }

    pub fn get_inner(&self) -> Inner<F> {
        self.clone().to_inner()
    }
}

impl<F: PRP> Default for Spongos<F> {
    fn default() -> Self {
        Self::init()
    }
}

impl<F: PRP> From<Inner<F>> for Spongos<F> {
    fn from(inner: Inner<F>) -> Self {
        let flags = inner.flags;
        Self {
            s: F::from_inner(&inner.into()),
            flags,
            pos: 0,
        }
    }
}

impl<F: PRP> From<&Inner<F>> for Spongos<F> {
    fn from(inner: &Inner<F>) -> Self {
        Self {
            s: F::from_inner(inner.into()),
            flags: inner.flags,
            pos: 0,
        }
    }
}

impl<F: PRP> From<Spongos<F>> for Inner<F> {
    fn from(s: Spongos<F>) -> Self {
        s.to_inner()
    }
}

impl<F: PRP> fmt::Debug for Spongos<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // write!(f, "{}[{:?}]", self.pos, hex::encode(self.s.outer().as_ref()))
        // write!(f, "[{}:{}]",
        //       hex::encode(&self.s.outer().as_ref()[..self.pos]),
        //       hex::encode(&self.s.outer().as_ref()[self.pos..]))
        write!(
            f,
            "[{}:{}|{}]",
            hex::encode(&self.s.outer().as_ref()[..self.pos]),
            hex::encode(&self.s.outer().as_ref()[self.pos..]),
            hex::encode(self.s.inner().as_ref())
        )
    }
}

/// Shortcut for `Spongos::init`.
pub fn init<F>() -> Spongos<F>
where
    F: PRP,
{
    Spongos::init()
}

/// Hash (one piece of) data with Spongos.
pub fn hash_data<F>(x: &[u8], y: &mut [u8])
where
    F: PRP,
{
    let mut s = Spongos::<F>::init();
    s.absorb(x);
    s.commit();
    s.squeeze(y).unwrap();
}

impl<F: PRP> Digest for Spongos<F>
where
    F::CapacitySize: Mul<U2>,
    <F::CapacitySize as Mul<U2>>::Output: ArrayLength<u8>,
{
    // This would normally result in U64, ie 512 bits needed for ed25519prehashed.
    type OutputSize = <F::CapacitySize as Mul<U2>>::Output;

    fn new() -> Self {
        Spongos::init()
    }

    fn update(&mut self, data: impl AsRef<[u8]>) {
        self.absorb(data.as_ref());
    }

    fn chain(mut self, data: impl AsRef<[u8]>) -> Self {
        self.absorb(data.as_ref());
        self
    }

    fn finalize(mut self) -> GenericArray<u8, Self::OutputSize> {
        self.commit();
        self.squeeze_arr().unwrap()
    }

    fn finalize_reset(&mut self) -> GenericArray<u8, Self::OutputSize> {
        self.commit();
        self.squeeze_arr().unwrap()
    }

    fn reset(&mut self) {
        *self = Self::new();
    }

    fn output_size() -> usize {
        64
    }

    fn digest(data: &[u8]) -> GenericArray<u8, Self::OutputSize> {
        let mut result = GenericArray::default();
        hash_data::<F>(data, result.as_mut_slice());
        result
    }
}
