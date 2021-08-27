/// Variable-size array of bytes, the size is not known at compile time and is encoded in binary representation.
#[derive(Copy, Clone, Default)]
pub struct Key(pub iota_streams_core::sponge::Key);

impl Key {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes.into())
    }
}

impl AsRef<[u8]> for Key {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl AsMut<[u8]> for Key {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl<'a> From<&'a iota_streams_core::sponge::Key> for &'a Key {
    fn from(key: &'a iota_streams_core::sponge::Key) -> Self {
        unsafe { &*(key.as_ptr() as *const Key) }
    }
}
