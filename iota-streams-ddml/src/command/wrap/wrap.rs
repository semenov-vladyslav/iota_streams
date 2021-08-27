use iota_streams_core::Result;

use crate::types::{
    size_bytes,
    Size,
};

/// Helper trait for wrapping (encoding/absorbing) trint3s.
pub(crate) trait Wrap {
    fn wrap_u8(&mut self, u: u8) -> Result<&mut Self>;
    fn wrap_u8_unchecked_zero(&mut self, u: u8) -> Result<&mut Self> {
        self.wrap_u8(u)
    }
    fn wrap_u16(&mut self, u: u16) -> Result<&mut Self> {
        self.wrapn(&u.to_be_bytes())
    }
    fn wrap_u32(&mut self, u: u32) -> Result<&mut Self> {
        self.wrapn(&u.to_be_bytes())
    }
    fn wrap_u64(&mut self, u: u64) -> Result<&mut Self> {
        self.wrapn(&u.to_be_bytes())
    }
    fn wrap_size(&mut self, size: Size) -> Result<&mut Self> where {
        let d = size_bytes(size.0);
        self.wrap_u8_unchecked_zero(d as u8)?;
        let n = size.0;
        for s in (0..d).rev() {
            let r = ((n >> (s << 3)) & 0xff) as u8;
            self.wrap_u8(r)?;
        }

        Ok(self)
    }
    fn wrapn(&mut self, v: &[u8]) -> Result<&mut Self> {
        for u in v {
            self.wrap_u8(*u)?;
        }
        Ok(self)
    }
}
