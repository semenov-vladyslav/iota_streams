use core::fmt;

/// DDML `size_t` type, unsigned.
#[derive(PartialEq, Eq, PartialOrd, Ord, Copy, Clone, Debug, Default)]
pub struct Size(pub usize);

/// Number of bytes needed to encode a value of `size_t` type.
pub fn size_bytes(mut n: usize) -> usize {
    let mut d = 0_usize;
    while n > 0 {
        n >>= 8;
        d += 1;
    }
    d
}

pub fn sizeof_sizet(n: usize) -> usize {
    size_bytes(n) + 1
}

impl fmt::Display for Size {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Size({})", self.0)
    }
}
