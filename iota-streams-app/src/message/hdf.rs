use core::fmt;
use iota_streams_core::{
    async_trait,
    prelude::Box,
    Result
};

use iota_streams_core::{
    sponge::prp::PRP,
    try_or,
    Errors::*,
};
use iota_streams_core_edsig::signature::ed25519;
use iota_streams_ddml::{
    command::*,
    io,
    types::{
        typenum::{
            U2,
            U3,
        },
        *,
    },
};

use super::*;
use crate::identifier::Identifier;

pub const FLAG_BRANCHING_MASK: u8 = 1;

#[derive(Clone)]
#[allow(clippy::upper_case_acronyms)]
pub struct HDF<Link> {
    pub link: Link,
    pub encoding: Uint8,
    pub version: Uint8,
    // message type is 4 bits
    pub content_type: u8,
    // payload length is 10 bits
    pub payload_length: usize,
    pub frame_type: Uint8,
    // frame count is 22 bits
    pub payload_frame_count: u32,
    pub previous_msg_link: Bytes,
    pub seq_num: Uint64,
    pub sender_id: Identifier,
}

impl<Link: Default> HDF<Link> {
    pub fn new(link: Link) -> Self {
        Self {
            link,
            encoding: UTF8,
            version: STREAMS_1_VER,
            content_type: 0,
            payload_length: 0,
            frame_type: HDF_ID,
            payload_frame_count: 0,
            previous_msg_link: Bytes::default(),
            seq_num: Uint64(0),
            sender_id: Identifier::EdPubKey(ed25519::PublicKey::default().into()),
        }
    }

    pub fn with_content_type(mut self, content_type: u8) -> Result<Self> {
        try_or!(content_type < 0x10, ValueOutOfRange(0x10_usize, content_type as usize))?;
        self.content_type = content_type;
        Ok(self)
    }

    pub fn get_content_type(&self) -> u8 {
        self.content_type
    }

    pub fn with_payload_length(mut self, payload_length: usize) -> Result<Self> {
        try_or!(payload_length < 0x0400, MaxSizeExceeded(0x0400_usize, payload_length))?;
        self.payload_length = payload_length;
        Ok(self)
    }

    pub fn get_payload_length(&self) -> usize {
        self.payload_length
    }

    pub fn with_payload_frame_count(mut self, payload_frame_count: u32) -> Result<Self> {
        try_or!(
            payload_frame_count < 0x400000,
            MaxSizeExceeded(0x400000_usize, payload_frame_count as usize)
        )?;
        self.payload_frame_count = payload_frame_count;
        Ok(self)
    }

    pub fn get_payload_frame_count(&self) -> u32 {
        self.payload_frame_count
    }

    pub fn with_seq_num(mut self, seq_num: u32) -> Self {
        self.seq_num = Uint64(seq_num as u64);
        self
    }

    pub fn get_seq_num(&self) -> u64 {
        self.seq_num.0
    }

    pub fn with_identifier(mut self, id: &Identifier) -> Self {
        self.sender_id = *id;
        self
    }

    pub fn get_identifier(&self) -> &Identifier {
        &self.sender_id
    }

    pub fn with_previous_msg_link(mut self, previous_msg_link: Bytes) -> Self {
        self.previous_msg_link = previous_msg_link;
        self
    }

    pub fn get_previous_msg_link(&self) -> &Bytes {
        &self.previous_msg_link
    }

    pub fn new_with_fields(
        link: Link,
        previous_msg_link: Bytes,
        content_type: u8,
        payload_length: usize,
        seq_num: u64,
        identifier: &Identifier,
    ) -> Result<Self> {
        try_or!(content_type < 0x10, ValueOutOfRange(0x10_usize, content_type as usize))?;
        try_or!(payload_length < 0x0400, MaxSizeExceeded(0x0400_usize, payload_length))?;
        Ok(Self {
            encoding: UTF8,
            version: STREAMS_1_VER,
            content_type,
            payload_length,
            frame_type: HDF_ID,
            payload_frame_count: 0,
            previous_msg_link,
            link,
            seq_num: Uint64(seq_num),
            sender_id: *identifier,
        })
    }
}

impl<Link: Default> Default for HDF<Link> {
    fn default() -> Self {
        Self {
            encoding: UTF8,
            version: STREAMS_1_VER,
            content_type: 0,
            payload_length: 0,
            frame_type: HDF_ID,
            payload_frame_count: 0,
            previous_msg_link: Bytes::default(),
            link: Link::default(),
            seq_num: Uint64(0),
            sender_id: Identifier::EdPubKey(ed25519::PublicKey::default().into()),
        }
    }
}

impl<Link> fmt::Debug for HDF<Link>
where
    Link: fmt::Debug + Default,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{encoding: {:?}, version: {:?}, content_type: {:?}, payload_length: {:?}}}",
            self.encoding,
            self.version,
            self.get_content_type(),
            self.get_payload_length()
        )
    }
}

#[async_trait]
impl<F, Link> ContentSizeof<F> for HDF<Link>
where
    F: PRP,
    Link: AbsorbExternalFallback<F>,
{
    async fn sizeof<'c>(&self, ctx: &'c mut sizeof::Context<F>) -> Result<&'c mut sizeof::Context<F>> {
        let content_type_and_payload_length = NBytes::<U2>::default();
        let payload_frame_count = NBytes::<U3>::default();
        ctx.absorb(self.encoding)?
            .absorb(self.version)?
            .skip(&content_type_and_payload_length)?
            .absorb(External(Uint8(self.content_type << 4)))?
            .absorb(self.frame_type)?
            .skip(&payload_frame_count)?
            .absorb(External(Fallback(&self.link)))?
            .absorb(&self.previous_msg_link)?
            .skip(self.seq_num)?;

        self.sender_id.sizeof(ctx).await?;

        Ok(ctx)
    }
}

#[async_trait]
impl<F, Link, Store> ContentWrap<F, Store> for HDF<Link>
where
    F: PRP,
    Link: AbsorbExternalFallback<F>,
    Store: Send + Sync,
{
    async fn wrap<'c, OS: io::OStream>(
        &self,
        _store: &Store,
        ctx: &'c mut wrap::Context<F, OS>,
    ) -> Result<&'c mut wrap::Context<F, OS>> {
        let content_type_and_payload_length = {
            let mut nbytes = NBytes::<U2>::default();
            let v = nbytes.as_mut();
            v[0] = (self.content_type << 4) | ((self.payload_length >> 8) as u8 & 0x03);
            v[1] = self.payload_length as u8;
            nbytes
        };
        let payload_frame_count = {
            let mut nbytes = NBytes::<U3>::default();
            let v = nbytes.as_mut();
            let x = self.payload_frame_count.to_be_bytes();
            v[0] = x[1] & 0x3f;
            v[1] = x[2];
            v[2] = x[3];
            nbytes
        };

        ctx.absorb(self.encoding)?
            .absorb(self.version)?
            .skip(&content_type_and_payload_length)?
            .absorb(External(Uint8(self.content_type << 4)))?
            .absorb(self.frame_type)?
            .skip(&payload_frame_count)?
            .absorb(External(Fallback(&self.link)))?
            .absorb(&self.previous_msg_link)?
            .skip(self.seq_num)?;

        self.sender_id.wrap(_store, ctx).await?;

        Ok(ctx)
    }
}

#[async_trait]
impl<F, Link, Store> ContentUnwrap<F, Store> for HDF<Link>
where
    F: PRP,
    Link: AbsorbExternalFallback<F> + std::fmt::Debug + Clone,
    Store: Send + Sync,
{
    async fn unwrap<'c, IS: io::IStream>(
        &mut self,
        _store: &Store,
        ctx: &'c mut unwrap::Context<F, IS>,
    ) -> Result<&'c mut unwrap::Context<F, IS>> {
        let mut content_type_and_payload_length = NBytes::<U2>::default();
        let mut payload_frame_count = NBytes::<U3>::default();

        ctx.absorb(&mut self.encoding)?
            .absorb(&mut self.version)?
            .guard(
                self.version == STREAMS_1_VER,
                InvalidMsgVersion(STREAMS_1_VER.0, self.version.0),
            )?
            .skip(&mut content_type_and_payload_length)?;
        {
            let v = content_type_and_payload_length.as_ref();
            try_or!(0 == v[0] & 0x0c, InvalidBitReservation)?;
            self.content_type = v[0] >> 4;
            self.payload_length = (((v[0] & 0x03) as usize) << 8) | (v[1] as usize);
        }

        ctx.absorb(External(Uint8(self.content_type << 4)))?
            .absorb(&mut self.frame_type)?
            .guard(self.frame_type == HDF_ID, InvalidMsgType(HDF_ID.0, self.frame_type.0))?
            .skip(&mut payload_frame_count)?;
        {
            let v = payload_frame_count.as_ref();
            try_or!(0 == v[0] & 0xc0, InvalidBitReservation)?;
            let mut x = [0_u8; 4];
            x[1] = v[0];
            x[2] = v[1];
            x[3] = v[2];
            self.payload_frame_count = u32::from_be_bytes(x);
        }

        ctx.absorb(External(Fallback(&self.link)))?
            .absorb(&mut self.previous_msg_link)?
            .skip(&mut self.seq_num)?;

        let (id, ctx) = Identifier::unwrap_new(_store, ctx).await?;
        self.sender_id = id;

        Ok(ctx)
    }
}
