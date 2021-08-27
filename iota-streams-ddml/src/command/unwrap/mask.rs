use core::mem;
use iota_streams_core::Result;

use super::{
    unwrap::*,
    Context,
};
use crate::{
    command::Mask,
    io,
    types::{
        ArrayLength,
        Bytes,
        Key,
        NBytes,
        Size,
        Uint16,
        Uint32,
        Uint64,
        Uint8,
    },
};
use iota_streams_core::{
    key_exchange::x25519,
    signature::ed25519,
    sponge::prp::PRP,
    wrapped_err,
    Errors::PublicKeyGenerationFailure,
    WrappedError,
};

struct MaskContext<F, IS> {
    ctx: Context<F, IS>,
}
impl<F, IS> AsMut<MaskContext<F, IS>> for Context<F, IS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut MaskContext<F, IS> {
        unsafe { mem::transmute::<&'a mut Context<F, IS>, &'a mut MaskContext<F, IS>>(self) }
    }
}
impl<F, IS> AsMut<Context<F, IS>> for MaskContext<F, IS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut Context<F, IS> {
        unsafe { mem::transmute::<&'a mut MaskContext<F, IS>, &'a mut Context<F, IS>>(self) }
    }
}

impl<F: PRP, IS: io::IStream> Unwrap for MaskContext<F, IS> {
    fn unwrap_u8(&mut self, u: &mut u8) -> Result<&mut Self> {
        let y = self.ctx.stream.try_advance(1)?;
        let mut x = [0_u8; 1];
        self.ctx.spongos.decrypt(y, &mut x)?;
        *u = x[0];
        Ok(self)
    }
    fn unwrap_u8_unchecked_zero(&mut self, u: &mut u8) -> Result<&mut Self> {
        let y = self.ctx.stream.try_advance(1)?;
        *u = self.ctx.spongos.decrypt1z(y[0])?;
        Ok(self)
    }
    fn unwrapn(&mut self, bytes: &mut [u8]) -> Result<&mut Self> {
        let y = self.ctx.stream.try_advance(bytes.len())?;
        // See corresponding comment in command::wrap::mask.
        if !bytes.is_empty() {
            self.ctx.spongos.decrypt(y, bytes)?;
        }
        Ok(self)
    }
}

fn unwrap_mask_u8<'a, F: PRP, IS: io::IStream>(
    ctx: &'a mut MaskContext<F, IS>,
    u: &mut Uint8,
) -> Result<&'a mut MaskContext<F, IS>> {
    ctx.unwrap_u8(&mut u.0)
}
fn unwrap_mask_u16<'a, F: PRP, IS: io::IStream>(
    ctx: &'a mut MaskContext<F, IS>,
    u: &mut Uint16,
) -> Result<&'a mut MaskContext<F, IS>> {
    ctx.unwrap_u16(&mut u.0)
}
fn unwrap_mask_u32<'a, F: PRP, IS: io::IStream>(
    ctx: &'a mut MaskContext<F, IS>,
    u: &mut Uint32,
) -> Result<&'a mut MaskContext<F, IS>> {
    ctx.unwrap_u32(&mut u.0)
}
fn unwrap_mask_u64<'a, F: PRP, IS: io::IStream>(
    ctx: &'a mut MaskContext<F, IS>,
    u: &mut Uint64,
) -> Result<&'a mut MaskContext<F, IS>> {
    ctx.unwrap_u64(&mut u.0)
}
fn unwrap_mask_size<'a, F: PRP, IS: io::IStream>(
    ctx: &'a mut MaskContext<F, IS>,
    size: &mut Size,
) -> Result<&'a mut MaskContext<F, IS>> {
    ctx.unwrap_size(size)
}
fn unwrap_mask_bytes<'a, F: PRP, IS: io::IStream>(
    ctx: &'a mut MaskContext<F, IS>,
    bytes: &mut [u8],
) -> Result<&'a mut MaskContext<F, IS>> {
    ctx.unwrapn(bytes)
}

impl<'a, F: PRP, IS: io::IStream> Mask<&'a mut Uint8> for Context<F, IS> {
    fn mask(&mut self, u: &'a mut Uint8) -> Result<&mut Self> {
        Ok(unwrap_mask_u8(self.as_mut(), u)?.as_mut())
    }
}

impl<'a, F: PRP, IS: io::IStream> Mask<&'a mut Uint16> for Context<F, IS> {
    fn mask(&mut self, u: &'a mut Uint16) -> Result<&mut Self> {
        Ok(unwrap_mask_u16(self.as_mut(), u)?.as_mut())
    }
}

impl<'a, F: PRP, IS: io::IStream> Mask<&'a mut Uint32> for Context<F, IS> {
    fn mask(&mut self, u: &'a mut Uint32) -> Result<&mut Self> {
        Ok(unwrap_mask_u32(self.as_mut(), u)?.as_mut())
    }
}

impl<'a, F: PRP, IS: io::IStream> Mask<&'a mut Uint64> for Context<F, IS> {
    fn mask(&mut self, u: &'a mut Uint64) -> Result<&mut Self> {
        Ok(unwrap_mask_u64(self.as_mut(), u)?.as_mut())
    }
}

impl<'a, F: PRP, IS: io::IStream> Mask<&'a mut Size> for Context<F, IS> {
    fn mask(&mut self, size: &'a mut Size) -> Result<&mut Self> {
        Ok(unwrap_mask_size(self.as_mut(), size)?.as_mut())
    }
}

impl<'a, F: PRP, N: ArrayLength<u8>, IS: io::IStream> Mask<&'a mut NBytes<N>> for Context<F, IS> {
    fn mask(&mut self, nbytes: &'a mut NBytes<N>) -> Result<&mut Self> {
        Ok(unwrap_mask_bytes(self.as_mut(), nbytes.as_mut_slice())?.as_mut())
    }
}

impl<'a, F: PRP, IS: io::IStream> Mask<&'a mut Key> for Context<F, IS> {
    fn mask(&mut self, key: &'a mut Key) -> Result<&mut Self> {
        Ok(unwrap_mask_bytes(self.as_mut(), key.as_mut())?.as_mut())
    }
}

impl<'a, F: PRP, IS: io::IStream> Mask<&'a mut Bytes> for Context<F, IS> {
    fn mask(&mut self, bytes: &'a mut Bytes) -> Result<&mut Self> {
        let mut size = Size(0);
        self.mask(&mut size)?;
        // TODO: Should there be a max size check? Otherwise resize on the next line might eat all memory.
        (bytes.0).resize(size.0, 0);
        Ok(unwrap_mask_bytes(self.as_mut(), &mut (bytes.0)[..])?.as_mut())
    }
}

impl<'a, F: PRP, IS: io::IStream> Mask<&'a mut x25519::PublicKey> for Context<F, IS> {
    fn mask(&mut self, pk: &'a mut x25519::PublicKey) -> Result<&mut Self> {
        let mut bytes = [0_u8; 32];
        unwrap_mask_bytes(self.as_mut(), &mut bytes)?;
        *pk = x25519::PublicKey::from(bytes);
        Ok(self)
    }
}

impl<'a, F: PRP, IS: io::IStream> Mask<&'a mut ed25519::PublicKey> for Context<F, IS> {
    fn mask(&mut self, pk: &'a mut ed25519::PublicKey) -> Result<&mut Self> {
        let mut bytes = [0_u8; ed25519::PUBLIC_KEY_LENGTH];
        unwrap_mask_bytes(self.as_mut(), &mut bytes)?;
        match ed25519::PublicKey::try_from_bytes(bytes) {
            Ok(apk) => {
                *pk = apk;
                Ok(self)
            }
            Err(e) => Err(wrapped_err!(PublicKeyGenerationFailure, WrappedError(e))),
        }
    }
}
