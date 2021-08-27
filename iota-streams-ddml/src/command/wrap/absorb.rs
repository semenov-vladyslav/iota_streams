use core::mem;
use iota_streams_core::Result;

use super::{
    wrap::*,
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
    key_exchange::x25519,
    signature::ed25519,
    sponge::prp::PRP,
};

struct AbsorbContext<F, OS> {
    ctx: Context<F, OS>,
}
impl<F, OS> AsMut<AbsorbContext<F, OS>> for Context<F, OS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut AbsorbContext<F, OS> {
        unsafe { mem::transmute::<&'a mut Context<F, OS>, &'a mut AbsorbContext<F, OS>>(self) }
    }
}
impl<F, OS> AsMut<Context<F, OS>> for AbsorbContext<F, OS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut Context<F, OS> {
        unsafe { mem::transmute::<&'a mut AbsorbContext<F, OS>, &'a mut Context<F, OS>>(self) }
    }
}

impl<F: PRP, OS: io::OStream> Wrap for AbsorbContext<F, OS> {
    fn wrap_u8(&mut self, u: u8) -> Result<&mut Self> {
        let slice = self.ctx.stream.try_advance(1)?;
        slice[0] = u;
        self.ctx.spongos.absorb(slice);
        Ok(self)
    }
    fn wrapn(&mut self, bytes: &[u8]) -> Result<&mut Self> {
        self.ctx.spongos.absorb(bytes);
        self.ctx.stream.try_advance(bytes.len())?.copy_from_slice(bytes);
        Ok(self)
    }
}

fn wrap_absorb_u8<F: PRP, OS: io::OStream>(
    ctx: &mut AbsorbContext<F, OS>,
    u: Uint8,
) -> Result<&mut AbsorbContext<F, OS>> {
    ctx.wrap_u8(u.0)
}
fn wrap_absorb_u16<F: PRP, OS: io::OStream>(
    ctx: &mut AbsorbContext<F, OS>,
    u: Uint16,
) -> Result<&mut AbsorbContext<F, OS>> {
    ctx.wrap_u16(u.0)
}
fn wrap_absorb_u32<F: PRP, OS: io::OStream>(
    ctx: &mut AbsorbContext<F, OS>,
    u: Uint32,
) -> Result<&mut AbsorbContext<F, OS>> {
    ctx.wrap_u32(u.0)
}
fn wrap_absorb_u64<F: PRP, OS: io::OStream>(
    ctx: &mut AbsorbContext<F, OS>,
    u: Uint64,
) -> Result<&mut AbsorbContext<F, OS>> {
    ctx.wrap_u64(u.0)
}
fn wrap_absorb_size<F: PRP, OS: io::OStream>(
    ctx: &mut AbsorbContext<F, OS>,
    size: Size,
) -> Result<&mut AbsorbContext<F, OS>> {
    ctx.wrap_size(size)
}
fn wrap_absorb_bytes<'a, F: PRP, OS: io::OStream>(
    ctx: &'a mut AbsorbContext<F, OS>,
    bytes: &[u8],
) -> Result<&'a mut AbsorbContext<F, OS>> {
    ctx.wrapn(bytes)
}

impl<'a, F: PRP, OS: io::OStream> Absorb<&'a Uint8> for Context<F, OS> {
    fn absorb(&mut self, u: &'a Uint8) -> Result<&mut Self> {
        Ok(wrap_absorb_u8(self.as_mut(), *u)?.as_mut())
    }
}

impl<F: PRP, OS: io::OStream> Absorb<Uint8> for Context<F, OS> {
    fn absorb(&mut self, u: Uint8) -> Result<&mut Self> {
        self.absorb(&u)
    }
}

impl<'a, F: PRP, OS: io::OStream> Absorb<&'a Uint16> for Context<F, OS> {
    fn absorb(&mut self, u: &'a Uint16) -> Result<&mut Self> {
        Ok(wrap_absorb_u16(self.as_mut(), *u)?.as_mut())
    }
}

impl<F: PRP, OS: io::OStream> Absorb<Uint16> for Context<F, OS> {
    fn absorb(&mut self, u: Uint16) -> Result<&mut Self> {
        self.absorb(&u)
    }
}

impl<'a, F: PRP, OS: io::OStream> Absorb<&'a Uint32> for Context<F, OS> {
    fn absorb(&mut self, u: &'a Uint32) -> Result<&mut Self> {
        Ok(wrap_absorb_u32(self.as_mut(), *u)?.as_mut())
    }
}

impl<F: PRP, OS: io::OStream> Absorb<Uint32> for Context<F, OS> {
    fn absorb(&mut self, u: Uint32) -> Result<&mut Self> {
        self.absorb(&u)
    }
}

impl<'a, F: PRP, OS: io::OStream> Absorb<&'a Uint64> for Context<F, OS> {
    fn absorb(&mut self, u: &'a Uint64) -> Result<&mut Self> {
        Ok(wrap_absorb_u64(self.as_mut(), *u)?.as_mut())
    }
}

impl<F: PRP, OS: io::OStream> Absorb<Uint64> for Context<F, OS> {
    fn absorb(&mut self, u: Uint64) -> Result<&mut Self> {
        self.absorb(&u)
    }
}

impl<'a, F: PRP, OS: io::OStream> Absorb<&'a Size> for Context<F, OS> {
    fn absorb(&mut self, size: &'a Size) -> Result<&mut Self> {
        Ok(wrap_absorb_size(self.as_mut(), *size)?.as_mut())
    }
}

impl<F: PRP, OS: io::OStream> Absorb<Size> for Context<F, OS> {
    fn absorb(&mut self, size: Size) -> Result<&mut Self> {
        self.absorb(&size)
    }
}

impl<'a, F: PRP, N: ArrayLength<u8>, OS: io::OStream> Absorb<&'a NBytes<N>> for Context<F, OS> {
    fn absorb(&mut self, nbytes: &'a NBytes<N>) -> Result<&mut Self> {
        Ok(wrap_absorb_bytes(self.as_mut(), nbytes.as_slice())?.as_mut())
    }
}

impl<'a, F: PRP, OS: io::OStream> Absorb<&'a Bytes> for Context<F, OS> {
    fn absorb(&mut self, bytes: &'a Bytes) -> Result<&mut Self> {
        self.absorb(Size((bytes.0).len()))?;
        Ok(wrap_absorb_bytes(self.as_mut(), &(bytes.0)[..])?.as_mut())
    }
}

impl<'a, F: PRP, OS: io::OStream> Absorb<&'a ed25519::PublicKey> for Context<F, OS> {
    fn absorb(&mut self, pk: &'a ed25519::PublicKey) -> Result<&mut Self> {
        Ok(wrap_absorb_bytes(self.as_mut(), &pk.to_bytes()[..])?.as_mut())
    }
}

impl<'a, F: PRP, OS: io::OStream> Absorb<&'a x25519::PublicKey> for Context<F, OS> {
    fn absorb(&mut self, pk: &'a x25519::PublicKey) -> Result<&mut Self> {
        Ok(wrap_absorb_bytes(self.as_mut(), pk.as_slice())?.as_mut())
    }
}

impl<'a, F, T: 'a + AbsorbFallback<F>, OS: io::OStream> Absorb<&'a Fallback<T>> for Context<F, OS> {
    fn absorb(&mut self, val: &'a Fallback<T>) -> Result<&mut Self> {
        (val.0).wrap_absorb(self)?;
        Ok(self)
    }
}
