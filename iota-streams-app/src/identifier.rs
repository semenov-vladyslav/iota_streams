use iota_streams_core::{
    err,
    key_exchange::x25519,
    prelude::{
        digest::generic_array::GenericArray,
        String,
        ToString,
        Vec,
    },
    psk::{
        self,
        Psk,
        PskId,
    },
    signature::ed25519,
    sponge::prp::PRP,
    wrapped_err,
    Errors::{
        BadOneof,
        IdentifierGenerationFailure,
        PskNotFound,
    },
    Result,
    WrappedError,
};

use iota_streams_ddml::{
    command::*,
    io,
    types::*,
};

use crate::message::*;

#[derive(Clone, Copy, Hash, PartialEq, Eq, Debug)]
pub enum Identifier {
    EdPubKey(ed25519::PublicKey),
    PskId(PskId),
}

impl Identifier {
    pub fn to_bytes(self) -> Vec<u8> {
        match self {
            Identifier::EdPubKey(id) => {
                let mut v = Vec::with_capacity(1 + ed25519::PUBLIC_KEY_LENGTH);
                v.resize(v.capacity(), 0);
                // 0 - tag for ed25519 public key
                v[0] = 0_u8;
                v[1..].copy_from_slice(id.as_slice());
                v
            }
            Identifier::PskId(id) => {
                let mut v = Vec::with_capacity(1 + psk::PSKID_SIZE);
                v.resize(v.capacity(), 0);
                // 1 - tag for PSKID
                v[0] = 1_u8;
                v[1..].copy_from_slice(id.as_slice());
                v
            }
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> iota_streams_core::Result<Self> {
        if bytes.is_empty() {
            return err!(IdentifierGenerationFailure);
        }
        match bytes[0] {
            0_u8 => {
                if bytes.len() != 1 + ed25519::PUBLIC_KEY_LENGTH {
                    return err!(IdentifierGenerationFailure);
                }
                let mut id = [0_u8; ed25519::PUBLIC_KEY_LENGTH];
                id.copy_from_slice(&bytes[1..]);
                Ok(Identifier::EdPubKey(ed25519::PublicKey::try_from_bytes(id).map_err(
                    |e| wrapped_err!(IdentifierGenerationFailure, WrappedError(e)),
                )?))
            }
            1_u8 => {
                if bytes.len() != 1 + psk::PSKID_SIZE {
                    return err!(IdentifierGenerationFailure);
                }
                let mut id = [0_u8; psk::PSKID_SIZE];
                id.copy_from_slice(&bytes[1..]);
                Ok(Identifier::PskId(GenericArray::clone_from_slice(&id)))
            }
            _ => err(IdentifierGenerationFailure),
        }
    }

    pub fn get_pk(&self) -> Option<&ed25519::PublicKey> {
        if let Identifier::EdPubKey(pk) = self {
            Some(pk)
        } else {
            None
        }
    }
}

impl ToString for Identifier {
    fn to_string(&self) -> String {
        hex::encode(self.to_bytes())
    }
}

impl From<ed25519::PublicKey> for Identifier {
    fn from(pk: ed25519::PublicKey) -> Self {
        Identifier::EdPubKey(pk)
    }
}

impl From<PskId> for Identifier {
    fn from(pskid: PskId) -> Self {
        Identifier::PskId(pskid)
    }
}

impl<F: PRP> ContentSizeof<F> for Identifier {
    fn sizeof<'c>(&self, ctx: &'c mut sizeof::Context<F>) -> Result<&'c mut sizeof::Context<F>> {
        match *self {
            Identifier::EdPubKey(pk) => {
                let oneof = Uint8(0);
                ctx.absorb(&oneof)?.absorb(&pk)?;
                Ok(ctx)
            }
            Identifier::PskId(pskid) => {
                let oneof = Uint8(1);
                ctx.absorb(&oneof)?.absorb(<&NBytes<psk::PskIdSize>>::from(&pskid))?;
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
                ctx.absorb(&oneof)?.absorb(&pk)?;
                Ok(ctx)
            }
            Identifier::PskId(pskid) => {
                let oneof = Uint8(1);
                ctx.absorb(&oneof)?.absorb(<&NBytes<psk::PskIdSize>>::from(&pskid))?;
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
        ctx.absorb(&mut oneof)?;
        match oneof.0 {
            0 => {
                let mut pk = ed25519::PublicKey::try_from_bytes([0_u8; ed25519::PUBLIC_KEY_LENGTH]).unwrap();
                ctx.absorb(&mut pk)?;
                let id = Identifier::EdPubKey(pk);
                Ok((id, ctx))
            }
            1 => {
                let mut pskid = PskId::default();
                ctx.absorb(<&mut NBytes<psk::PskIdSize>>::from(&mut pskid))?;
                let id = Identifier::PskId(pskid);
                Ok((id, ctx))
            }
            _ => err(BadOneof),
        }
    }
}

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
pub enum IdentifierInfoRef<'a, Info> {
    EdPubKey(&'a ed25519::PublicKey, &'a Info),
    PskId(&'a PskId, &'a Info),
}

impl<'a, Info> IdentifierInfoRef<'a, Info> {
    pub fn to_identifier(&self) -> Identifier {
        match *self {
            IdentifierInfoRef::EdPubKey(pk, _) => Identifier::EdPubKey(*pk),
            IdentifierInfoRef::PskId(pskid, _) => Identifier::PskId(*pskid),
        }
    }
}

impl<'a, Info> AsRef<Info> for IdentifierInfoRef<'a, Info> {
    fn as_ref(&self) -> &Info {
        match self {
            IdentifierInfoRef::EdPubKey(_, info) => info,
            IdentifierInfoRef::PskId(_, info) => info,
        }
    }
}

impl<'a, Info> From<IdentifierInfoRef<'a, Info>> for Identifier {
    fn from(r: IdentifierInfoRef<'a, Info>) -> Self {
        r.to_identifier()
    }
}

pub enum IdentifierInfoMut<'a, Info> {
    EdPubKey(&'a ed25519::PublicKey, &'a mut Info),
    PskId(&'a PskId, &'a mut Info),
}

impl<'a, Info> IdentifierInfoMut<'a, Info> {
    pub fn to_identifier(&self) -> Identifier {
        match *self {
            IdentifierInfoMut::EdPubKey(pk, _) => Identifier::EdPubKey(*pk),
            IdentifierInfoMut::PskId(pskid, _) => Identifier::PskId(*pskid),
        }
    }
}

impl<'a, Info> AsMut<Info> for IdentifierInfoMut<'a, Info> {
    fn as_mut(&mut self) -> &mut Info {
        match self {
            IdentifierInfoMut::EdPubKey(_, info) => info,
            IdentifierInfoMut::PskId(_, info) => info,
        }
    }
}

impl<'a, Info> From<IdentifierInfoMut<'a, Info>> for Identifier {
    fn from(r: IdentifierInfoMut<'a, Info>) -> Self {
        r.to_identifier()
    }
}

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
pub enum IdentifierKeyRef<'a> {
    EdPubKey(&'a ed25519::PublicKey, &'a x25519::PublicKey),
    PskId(&'a PskId, &'a Option<Psk>),
}

impl<'a> IdentifierKeyRef<'a> {
    pub fn to_identifier(&self) -> Identifier {
        match *self {
            IdentifierKeyRef::EdPubKey(pk, _) => Identifier::EdPubKey(*pk),
            IdentifierKeyRef::PskId(pskid, _) => Identifier::PskId(*pskid),
        }
    }
}

impl<'a> From<IdentifierKeyRef<'a>> for Identifier {
    fn from(r: IdentifierKeyRef<'a>) -> Self {
        r.to_identifier()
    }
}

impl<'a, F: PRP> ContentSizeof<F> for IdentifierKeyRef<'a> {
    fn sizeof<'c>(&self, ctx: &'c mut sizeof::Context<F>) -> Result<&'c mut sizeof::Context<F>> {
        match *self {
            IdentifierKeyRef::EdPubKey(pk, xpk) => {
                let oneof = Uint8(0);
                ctx.mask(&oneof)?.mask(pk)?.fork(|ctx| ctx.x25519(xpk, ()))
            }
            IdentifierKeyRef::PskId(pskid, Some(psk)) => {
                let oneof = Uint8(1);
                ctx.mask(&oneof)?
                    .mask(<&NBytes<psk::PskIdSize>>::from(pskid))?
                    .fork(|ctx| ctx.absorb_key(External(psk.into()))?.commit())
            }
            IdentifierKeyRef::PskId(_pskid, None) => {
                err!(PskNotFound)
            }
        }
    }
}

impl<'a, F: PRP, Store> ContentWrap<F, Store> for IdentifierKeyRef<'a> {
    fn wrap<'c, OS: io::OStream>(
        &self,
        _store: &Store,
        ctx: &'c mut wrap::Context<F, OS>,
    ) -> Result<&'c mut wrap::Context<F, OS>> {
        match *self {
            IdentifierKeyRef::EdPubKey(pk, xpk) => {
                let oneof = Uint8(0);
                ctx.mask(&oneof)?.mask(pk)?.fork(|ctx| ctx.x25519(xpk, ()))
            }
            IdentifierKeyRef::PskId(pskid, Some(psk)) => {
                let oneof = Uint8(1);
                ctx.mask(&oneof)?
                    .mask(<&NBytes<psk::PskIdSize>>::from(pskid))?
                    .fork(|ctx| ctx.absorb_key(External(psk.into()))?.commit())
            }
            IdentifierKeyRef::PskId(_pskid, None) => {
                err!(PskNotFound)
            }
        }
    }
}
