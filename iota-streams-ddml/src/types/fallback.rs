use crate::command::{
    sizeof,
    unwrap,
    wrap,
};
use iota_streams_core::Result;

use crate::io;

pub struct Fallback<T>(pub T);

impl<T> From<T> for Fallback<T> {
    fn from(t: T) -> Self {
        Self(t)
    }
}

impl<'a, T> From<&'a T> for &'a Fallback<T> {
    fn from(t: &T) -> Self {
        unsafe { core::mem::transmute(t) }
    }
}

impl<'a, T> From<&'a mut T> for &'a mut Fallback<T> {
    fn from(t: &mut T) -> Self {
        unsafe { core::mem::transmute(t) }
    }
}

// Can't impl Into<T> for Fallback<T> due to conflict with core::convert::Into impl for T

impl<T> AsRef<T> for Fallback<T> {
    fn as_ref(&self) -> &T {
        &(self.0)
    }
}

impl<T> AsMut<T> for Fallback<T> {
    fn as_mut(&mut self) -> &mut T {
        &mut (self.0)
    }
}

/// Trait allows for custom (non-standard DDML) types to be Absorb.
pub trait AbsorbFallback<F> {
    fn sizeof_absorb(&self, ctx: &mut sizeof::Context<F>) -> Result<()>;
    fn wrap_absorb<OS: io::OStream>(&self, ctx: &mut wrap::Context<F, OS>) -> Result<()>;
    fn unwrap_absorb<IS: io::IStream>(&mut self, ctx: &mut unwrap::Context<F, IS>) -> Result<()>;
}

/// Trait allows for custom (non-standard DDML) types to be AbsorbExternal.
/// It is usually implemented for "absolute" link types that are not specified
/// in DDML and domain specific.
///
/// Note, that "absolute" links are absorbed in the message header.
pub trait AbsorbExternalFallback<F>: Send + Sync {
    fn sizeof_absorb_external(&self, ctx: &mut sizeof::Context<F>) -> Result<()>;
    fn wrap_absorb_external<OS: io::OStream>(&self, ctx: &mut wrap::Context<F, OS>) -> Result<()>;
    fn unwrap_absorb_external<IS: io::IStream>(&self, ctx: &mut unwrap::Context<F, IS>) -> Result<()>;
}

/// Trait allows for custom (non-standard DDML) types to be Absorb.
/// It is usually implemented for "relative" link types that are not specified
/// in DDML and domain specific.
///
/// Note, that "relative" links are usually skipped and joined in the message content.
pub trait SkipFallback<F> {
    fn sizeof_skip(&self, ctx: &mut sizeof::Context<F>) -> Result<()>;
    fn wrap_skip<OS: io::OStream>(&self, ctx: &mut wrap::Context<F, OS>) -> Result<()>;
    fn unwrap_skip<IS: io::IStream>(&mut self, ctx: &mut unwrap::Context<F, IS>) -> Result<()>;
}
