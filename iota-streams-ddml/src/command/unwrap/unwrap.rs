use iota_streams_core::Result;

use crate::types::Size;

/// Helper trait for unwrapping (decoding/absorbing) uint8s.
pub(crate) trait Unwrap {
    fn unwrap_u8(&mut self, u: &mut u8) -> Result<&mut Self>;
    fn unwrap_u8_unchecked_zero(&mut self, u: &mut u8) -> Result<&mut Self> {
        self.unwrap_u8(u)
    }
    fn unwrap_u16(&mut self, u: &mut u16) -> Result<&mut Self> {
        let mut v = [0_u8; 2];
        self.unwrapn(&mut v)?;
        *u = u16::from_be_bytes(v);
        Ok(self)
    }
    fn unwrap_u32(&mut self, u: &mut u32) -> Result<&mut Self> {
        let mut v = [0_u8; 4];
        self.unwrapn(&mut v)?;
        *u = u32::from_be_bytes(v);
        Ok(self)
    }
    fn unwrap_u64(&mut self, u: &mut u64) -> Result<&mut Self> {
        let mut v = [0_u8; 8];
        self.unwrapn(&mut v)?;
        *u = u64::from_be_bytes(v);
        Ok(self)
    }
    fn unwrap_size(&mut self, size: &mut Size) -> Result<&mut Self> where {
        let mut d = 0_u8;
        // Special case to allow unchecked (ie. without key) decrypt of `0`
        self.unwrap_u8_unchecked_zero(&mut d)?;

        let mut m = 0_usize;
        while 0 < d {
            d -= 1;
            let mut t = 0_u8;
            self.unwrap_u8(&mut t)?;
            m = (m << 8) | t as usize;
        }

        size.0 = m;
        Ok(self)
    }
    fn unwrapn(&mut self, v: &mut [u8]) -> Result<&mut Self> {
        for u in v {
            self.unwrap_u8(u)?;
        }
        Ok(self)
    }
}
