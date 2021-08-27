use core::{
    fmt,
    hash,
    str::FromStr,
};

use iota_streams_core::{
    prelude::{
        hex,
        Vec,
    },
    Error,
};

/// Variable-size array of bytes, the size is not known at compile time and is encoded in binary representation.
#[derive(Eq, Clone, Debug, Default)]
pub struct Bytes(pub Vec<u8>);

impl Bytes {
    pub fn new() -> Self {
        Self(Vec::new())
    }
}

impl fmt::Display for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

impl PartialEq for Bytes {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}

impl hash::Hash for Bytes {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        (self.0).hash(state);
    }
}

impl FromStr for Bytes {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        let mut v = Vec::new();
        v.extend_from_slice(s.as_bytes());
        Ok(Bytes(v))
    }
}

impl<'a> From<&'a Vec<u8>> for &'a Bytes {
    fn from(v: &Vec<u8>) -> &Bytes {
        unsafe { &*(v as *const Vec<u8> as *const Bytes) }
    }
}

impl<'a> From<&'a mut Vec<u8>> for &'a mut Bytes {
    fn from(v: &mut Vec<u8>) -> &mut Bytes {
        unsafe { &mut *(v as *mut Vec<u8> as *mut Bytes) }
    }
}
