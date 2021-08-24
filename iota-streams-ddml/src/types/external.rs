pub use iota_streams_core::prelude::generic_array::ArrayLength;

use super::NBytes;

/// DDML `external` modifier, it changes behaviour of commands in the following way.
/// The external field is not encoded in trinary representation and the value is stored in the environment implicitly.
#[derive(PartialEq, Eq, Copy, Clone, Debug, Default)]
pub struct External<T>(pub T);

impl<'a, T, N> From<T> for External<&'a NBytes<N>>
where
    T: Into<&'a NBytes<N>>,
    N: ArrayLength<u8>,
{
    fn from(origin: T) -> Self {
        Self(origin.into())
    }
}
