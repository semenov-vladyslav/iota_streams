use iota_streams_core::{
    err,
    prelude::{
        digest::generic_array::GenericArray,
        Vec,
    },
    psk::{
        self,
        PskId,
        PSKID_SIZE,
    },
    sponge::prp::PRP,
    Error,
    Errors::{
        BadOneof,
        IdentifierGenerationFailure,
    },
    Result,
};

use iota_streams_core_edsig::signature::ed25519;

use iota_streams_ddml::{
    command::*,
    io,
    types::*,
};

use crate::message::*;

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
pub enum Identifier {
    EdPubKey(ed25519::PublicKeyWrap),
    PskId(PskId),
}

impl Identifier {
    pub fn to_bytes(self) -> Vec<u8> {
        match self {
            Identifier::EdPubKey(id) => id.0.as_bytes().to_vec(),
            Identifier::PskId(id) => id.to_vec(),
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> iota_streams_core::Result<Self> {
        match bytes.len() {
            ed25519::PUBLIC_KEY_LENGTH => Ok(Identifier::EdPubKey(
                ed25519::PublicKey::from_bytes(bytes).map_err(Error::msg)?.into(),
            )),
            PSKID_SIZE => Ok(Identifier::PskId(GenericArray::clone_from_slice(bytes))),
            _ => err(IdentifierGenerationFailure),
        }
    }

    pub fn get_pk(&self) -> Option<&ed25519::PublicKey> {
        if let Identifier::EdPubKey(pk) = self {
            Some(&pk.0)
        } else {
            None
        }
    }
}

impl From<ed25519::PublicKey> for Identifier {
    fn from(pk: ed25519::PublicKey) -> Self {
        Identifier::EdPubKey(pk.into())
    }
}

impl From<&PskId> for Identifier {
    fn from(pskid: &PskId) -> Self {
        Identifier::PskId(*pskid)
    }
}

impl<F: PRP> ContentSizeof<F> for Identifier {
    fn sizeof<'c>(&self, ctx: &'c mut sizeof::Context<F>) -> Result<&'c mut sizeof::Context<F>> {
        match *self {
            Identifier::EdPubKey(pk) => {
                let oneof = Uint8(0);
                ctx.mask(&oneof)?.mask(&pk.0)?;
                Ok(ctx)
            }
            Identifier::PskId(pskid) => {
                let oneof = Uint8(1);
                ctx.mask(&oneof)?.mask(<&NBytes<psk::PskIdSize>>::from(&pskid))?;
                Ok(ctx)
            }
        }
    }
}

impl<F: PRP, Store> ContentWrap<F, Store> for Identifier {
    fn wrap<'c, OS: io::OStream>(
        &self,
        _store: &Store,
        ctx: &'c mut wrap::Context<F, OS>,
    ) -> Result<&'c mut wrap::Context<F, OS>> {
        match *self {
            Identifier::EdPubKey(pk) => {
                let oneof = Uint8(0);
                ctx.mask(&oneof)?.mask(&pk.0)?;
                Ok(ctx)
            }
            Identifier::PskId(pskid) => {
                let oneof = Uint8(1);
                ctx.mask(&oneof)?.mask(<&NBytes<psk::PskIdSize>>::from(&pskid))?;
                Ok(ctx)
            }
        }
    }
}

impl<F: PRP, Store> ContentUnwrap<F, Store> for Identifier {
    fn unwrap<'c, IS: io::IStream>(
        &mut self,
        _store: &Store,
        ctx: &'c mut unwrap::Context<F, IS>,
    ) -> Result<&'c mut unwrap::Context<F, IS>> {
        let (id, ctx) = Self::unwrap_new(_store, ctx)?;
        *self = id;
        Ok(ctx)
    }
}

impl<F: PRP, Store> ContentUnwrapNew<F, Store> for Identifier {
    fn unwrap_new<'c, IS: io::IStream>(
        _store: &Store,
        ctx: &'c mut unwrap::Context<F, IS>,
    ) -> Result<(Self, &'c mut unwrap::Context<F, IS>)> {
        let mut oneof = Uint8(0);
        ctx.mask(&mut oneof)?;
        match oneof.0 {
            0 => {
                let mut pk = ed25519::PublicKey::default();
                ctx.mask(&mut pk)?;
                let id = Identifier::EdPubKey(ed25519::PublicKeyWrap(pk));
                Ok((id, ctx))
            }
            1 => {
                let mut pskid = PskId::default();
                ctx.mask(<&mut NBytes<psk::PskIdSize>>::from(&mut pskid))?;
                let id = Identifier::PskId(pskid);
                Ok((id, ctx))
            }
            _ => err(BadOneof),
        }
    }
}
