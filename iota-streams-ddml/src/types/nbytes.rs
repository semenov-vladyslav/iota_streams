use core::{
    convert::{
        AsMut,
        AsRef,
    },
    fmt,
};

// Reexport some often used types
pub use iota_streams_core::prelude::{
    generic_array::{
        ArrayLength,
        GenericArray,
    },
    hex,
    typenum::{
        marker_traits::Unsigned,
        U16,
        U32,
        U64,
    },
};

/// Fixed-size array of bytes, the size is known at compile time and is not encoded in binary representation.
#[derive(Clone, PartialEq, Eq, Debug, Default, Hash)]
pub struct NBytes<N: ArrayLength<u8>>(pub GenericArray<u8, N>);

impl<N> Copy for NBytes<N>
where
    N: ArrayLength<u8>,
    N::ArrayType: Copy,
{
}

impl<N: ArrayLength<u8>> fmt::Display for NBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

impl<N: ArrayLength<u8>> NBytes<N> {
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }
}

impl<N: ArrayLength<u8>> AsRef<[u8]> for NBytes<N> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<N: ArrayLength<u8>> AsMut<[u8]> for NBytes<N> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl<N: ArrayLength<u8>> From<GenericArray<u8, N>> for NBytes<N> {
    fn from(ga: GenericArray<u8, N>) -> Self {
        NBytes(ga)
    }
}

impl<'a, N: ArrayLength<u8>> From<&'a GenericArray<u8, N>> for &'a NBytes<N> {
    fn from(ga: &GenericArray<u8, N>) -> Self {
        unsafe { &*(ga.as_ptr() as *const NBytes<N>) }
    }
}

impl<'a, N: ArrayLength<u8>> From<&'a mut GenericArray<u8, N>> for &'a mut NBytes<N> {
    fn from(ga: &mut GenericArray<u8, N>) -> Self {
        unsafe { &mut *(ga.as_mut_ptr() as *mut NBytes<N>) }
    }
}

impl<N: ArrayLength<u8>> From<NBytes<N>> for GenericArray<u8, N> {
    fn from(bs: NBytes<N>) -> Self {
        bs.0
    }
}

impl<'a, N: ArrayLength<u8>> From<&'a [u8]> for &'a NBytes<N> {
    fn from(slice: &[u8]) -> &NBytes<N> {
        unsafe { &*(slice.as_ptr() as *const NBytes<N>) }
    }
}

impl<'a, N: ArrayLength<u8>> From<&'a mut [u8]> for &'a mut NBytes<N> {
    fn from(slice: &mut [u8]) -> &mut NBytes<N> {
        unsafe { &mut *(slice.as_mut_ptr() as *mut NBytes<N>) }
    }
}
