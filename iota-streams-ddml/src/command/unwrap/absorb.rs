use core::mem;

use super::{
    unwrap::*,
    Context,
};
use crate::{
    command::Absorb,
    io,
    types::{
        AbsorbFallback,
        ArrayLength,
        Bytes,
        Fallback,
        NBytes,
        Size,
        Uint16,
        Uint32,
        Uint64,
        Uint8,
    },
};
use iota_streams_core::{
    err,
    key_exchange::x25519,
    signature::ed25519,
    sponge::prp::PRP,
    Errors::PublicKeyGenerationFailure,
    Result,
};

struct AbsorbContext<F, IS> {
    ctx: Context<F, IS>,
}
impl<F, IS> AsMut<AbsorbContext<F, IS>> for Context<F, IS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut AbsorbContext<F, IS> {
        unsafe { mem::transmute::<&'a mut Context<F, IS>, &'a mut AbsorbContext<F, IS>>(self) }
    }
}
impl<F, IS> AsMut<Context<F, IS>> for AbsorbContext<F, IS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut Context<F, IS> {
        unsafe { mem::transmute::<&'a mut AbsorbContext<F, IS>, &'a mut Context<F, IS>>(self) }
    }
}

impl<F: PRP, IS: io::IStream> Unwrap for AbsorbContext<F, IS> {
    fn unwrap_u8(&mut self, u: &mut u8) -> Result<&mut Self> {
        let slice = self.ctx.stream.try_advance(1)?;
        *u = slice[0];
        self.ctx.spongos.absorb(slice);
        Ok(self)
    }
    fn unwrapn(&mut self, bytes: &mut [u8]) -> Result<&mut Self> {
        let slice = self.ctx.stream.try_advance(bytes.len())?;
        bytes.copy_from_slice(slice);
        self.ctx.spongos.absorb(bytes);
        Ok(self)
    }
}

fn unwrap_absorb_u8<'a, F: PRP, IS: io::IStream>(
    ctx: &'a mut AbsorbContext<F, IS>,
    u: &mut Uint8,
) -> Result<&'a mut AbsorbContext<F, IS>> {
    ctx.unwrap_u8(&mut u.0)
}
fn unwrap_absorb_u16<'a, F: PRP, IS: io::IStream>(
    ctx: &'a mut AbsorbContext<F, IS>,
    u: &mut Uint16,
) -> Result<&'a mut AbsorbContext<F, IS>> {
    ctx.unwrap_u16(&mut u.0)
}
fn unwrap_absorb_u32<'a, F: PRP, IS: io::IStream>(
    ctx: &'a mut AbsorbContext<F, IS>,
    u: &mut Uint32,
) -> Result<&'a mut AbsorbContext<F, IS>> {
    ctx.unwrap_u32(&mut u.0)
}
fn unwrap_absorb_u64<'a, F: PRP, IS: io::IStream>(
    ctx: &'a mut AbsorbContext<F, IS>,
    u: &mut Uint64,
) -> Result<&'a mut AbsorbContext<F, IS>> {
    ctx.unwrap_u64(&mut u.0)
}
fn unwrap_absorb_size<'a, F: PRP, IS: io::IStream>(
    ctx: &'a mut AbsorbContext<F, IS>,
    size: &mut Size,
) -> Result<&'a mut AbsorbContext<F, IS>> {
    ctx.unwrap_size(size)
}
fn unwrap_absorb_bytes<'a, F: PRP, IS: io::IStream>(
    ctx: &'a mut AbsorbContext<F, IS>,
    bytes: &mut [u8],
) -> Result<&'a mut AbsorbContext<F, IS>> {
    ctx.unwrapn(bytes)
}

impl<F: PRP, IS: io::IStream> Absorb<&mut Uint8> for Context<F, IS> {
    fn absorb(&mut self, u: &mut Uint8) -> Result<&mut Self> {
        Ok(unwrap_absorb_u8(self.as_mut(), u)?.as_mut())
    }
}

impl<F: PRP, IS: io::IStream> Absorb<&mut Uint16> for Context<F, IS> {
    fn absorb(&mut self, u: &mut Uint16) -> Result<&mut Self> {
        Ok(unwrap_absorb_u16(self.as_mut(), u)?.as_mut())
    }
}

impl<F: PRP, IS: io::IStream> Absorb<&mut Uint32> for Context<F, IS> {
    fn absorb(&mut self, u: &mut Uint32) -> Result<&mut Self> {
        Ok(unwrap_absorb_u32(self.as_mut(), u)?.as_mut())
    }
}

impl<F: PRP, IS: io::IStream> Absorb<&mut Uint64> for Context<F, IS> {
    fn absorb(&mut self, u: &mut Uint64) -> Result<&mut Self> {
        Ok(unwrap_absorb_u64(self.as_mut(), u)?.as_mut())
    }
}

impl<F: PRP, IS: io::IStream> Absorb<&mut Size> for Context<F, IS> {
    fn absorb(&mut self, size: &mut Size) -> Result<&mut Self> {
        Ok(unwrap_absorb_size(self.as_mut(), size)?.as_mut())
    }
}

impl<'a, F: PRP, N: ArrayLength<u8>, IS: io::IStream> Absorb<&'a mut NBytes<N>> for Context<F, IS> {
    fn absorb(&mut self, nbytes: &'a mut NBytes<N>) -> Result<&mut Self> {
        Ok(unwrap_absorb_bytes(self.as_mut(), nbytes.as_mut_slice())?.as_mut())
    }
}

impl<'a, F: PRP, IS: io::IStream> Absorb<&'a mut Bytes> for Context<F, IS> {
    fn absorb(&mut self, bytes: &'a mut Bytes) -> Result<&mut Self> {
        let mut size = Size(0);
        self.absorb(&mut size)?;
        (bytes.0).resize(size.0, 0);
        Ok(unwrap_absorb_bytes(self.as_mut(), &mut (bytes.0)[..])?.as_mut())
    }
}

impl<'a, F: PRP, IS: io::IStream> Absorb<&'a mut ed25519::PublicKey> for Context<F, IS> {
    fn absorb(&mut self, pk: &'a mut ed25519::PublicKey) -> Result<&mut Self> {
        let mut pk_bytes = [0_u8; ed25519::PUBLIC_KEY_LENGTH];
        unwrap_absorb_bytes(self.as_mut(), &mut pk_bytes)?;
        match ed25519::PublicKey::try_from_bytes(pk_bytes) {
            Ok(apk) => {
                *pk = apk;
                Ok(self)
            }
            Err(_) => err!(PublicKeyGenerationFailure),
        }
    }
}

impl<'a, F: PRP, IS: io::IStream> Absorb<&'a mut x25519::PublicKey> for Context<F, IS> {
    fn absorb(&mut self, pk: &'a mut x25519::PublicKey) -> Result<&mut Self> {
        let mut pk_bytes = [0_u8; 32];
        unwrap_absorb_bytes(self.as_mut(), &mut pk_bytes)?;
        *pk = x25519::PublicKey::from_bytes(pk_bytes);
        Ok(self)
    }
}

impl<'a, F, T: 'a + AbsorbFallback<F>, IS: io::IStream> Absorb<&'a mut Fallback<T>> for Context<F, IS> {
    fn absorb(&mut self, val: &'a mut Fallback<T>) -> Result<&mut Self> {
        (val.0).unwrap_absorb(self)?;
        Ok(self)
    }
}
