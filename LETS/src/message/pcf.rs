use alloc::{
    borrow::ToOwned,
    boxed::Box,
};
use core::convert::{
    TryFrom,
    TryInto,
};

use anyhow::{
    anyhow,
    ensure,
    Result,
};
use async_trait::async_trait;

use spongos::{
    ddml::{
        commands::{
            sizeof,
            unwrap,
            wrap,
            Absorb,
            Skip,
        },
        io,
        types::{
            NBytes,
            Uint8,
        },
    },
    PRP,
};

use crate::message::{
    content::{
        ContentSizeof,
        ContentUnwrap,
        ContentWrap,
    },
    version::{
        FINAL_PCF_ID,
        INIT_PCF_ID,
        INTER_PCF_ID,
    },
};

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[allow(clippy::upper_case_acronyms)]
pub struct PCF<Content> {
    frame_type: u8,
    // 22-bit field
    payload_frame_num: PayloadFrameNum,
    content: Content,
}

impl PCF<()> {
    fn new_init_frame() -> Self {
        Self {
            frame_type: INIT_PCF_ID,
            payload_frame_num: PayloadFrameNum::from_u32_unchecked(1),
            content: (),
        }
    }

    fn new_inter_frame() -> Self {
        Self {
            frame_type: INTER_PCF_ID,
            payload_frame_num: PayloadFrameNum::from_u32_unchecked(1),
            content: (),
        }
    }

    pub fn new_final_frame() -> Self {
        Self {
            frame_type: FINAL_PCF_ID,
            payload_frame_num: PayloadFrameNum::from_u32_unchecked(1),
            content: (),
        }
    }
}

impl<Content> Default for PCF<Content>
where
    Content: Default,
{
    fn default() -> Self {
        PCF::new_final_frame().with_content(Default::default())
    }
}

impl<Content> PCF<Content> {
    fn new(frame_type: u8, payload_frame_num: u32, content: Content) -> Result<Self> {
        Ok(Self {
            frame_type,
            payload_frame_num: payload_frame_num.try_into()?,
            content,
        })
    }

    pub fn with_content<T>(self, content: T) -> PCF<T> {
        PCF {
            frame_type: self.frame_type,
            payload_frame_num: self.payload_frame_num,
            content,
        }
    }

    pub(crate) fn change_content(&mut self, content: Content) {
        self.content = content;
    }

    pub fn content(&self) -> &Content {
        &self.content
    }

    pub fn into_content(self) -> Content {
        self.content
    }

    fn with_payload_frame_num(&mut self, payload_frame_num: u32) -> Result<&mut Self> {
        self.payload_frame_num = payload_frame_num.try_into()?;
        Ok(self)
    }

    fn payload_frame_num(&self) -> PayloadFrameNum {
        self.payload_frame_num
    }
}

#[async_trait(?Send)]
impl<Content> ContentSizeof<PCF<Content>> for sizeof::Context
where
    sizeof::Context: ContentSizeof<Content>,
{
    async fn sizeof(&mut self, pcf: &PCF<Content>) -> Result<&mut Self> {
        self.absorb(Uint8::new(pcf.frame_type))?
            .skip(pcf.payload_frame_num)?
            .sizeof(&pcf.content)
            .await?;
        Ok(self)
    }
}

#[async_trait(?Send)]
impl<F, OS, Content> ContentWrap<PCF<Content>> for wrap::Context<F, OS>
where
    F: PRP,
    OS: io::OStream,
    Self: ContentWrap<Content>,
{
    async fn wrap(&mut self, pcf: &mut PCF<Content>) -> Result<&mut Self>
    where
        Content: 'async_trait,
    {
        self.absorb(Uint8::new(pcf.frame_type))?
            .skip(pcf.payload_frame_num)?
            .wrap(&mut pcf.content)
            .await?;
        Ok(self)
    }
}

#[async_trait(?Send)]
impl<F, IS, Content> ContentUnwrap<PCF<Content>> for unwrap::Context<F, IS>
where
    F: PRP,
    IS: io::IStream,
    unwrap::Context<F, IS>: ContentUnwrap<Content>,
{
    async fn unwrap(&mut self, pcf: &mut PCF<Content>) -> Result<&mut Self> {
        let mut frame_type = Uint8::default();
        self.absorb(&mut frame_type)?
            .skip(&mut pcf.payload_frame_num)?
            .unwrap(&mut pcf.content)
            .await?;
        pcf.frame_type = frame_type.into();
        Ok(self)
    }
}

#[derive(Copy, Clone, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
struct PayloadFrameNum(u32);

impl PayloadFrameNum {
    fn from_u32(frame_num: u32) -> Result<Self> {
        Self::validate(frame_num)?;
        Ok(Self::from_u32_unchecked(frame_num))
    }

    fn from_u32_unchecked(frame_num: u32) -> Self {
        Self(frame_num)
    }

    fn validate(payload_frame_num: u32) -> Result<()> {
        ensure!(
            payload_frame_num >> 22 == 0,
            "got '{}', but payload-frame-num value cannot be greater than 22 bits",
            payload_frame_num
        );
        Ok(())
    }

    fn to_inner(self) -> u32 {
        self.0
    }
}

impl TryFrom<u32> for PayloadFrameNum {
    type Error = anyhow::Error;

    fn try_from(frame_num: u32) -> Result<Self> {
        Self::from_u32(frame_num)
    }
}

impl From<PayloadFrameNum> for NBytes<[u8; 3]> {
    fn from(frame_num: PayloadFrameNum) -> Self {
        let bytes = frame_num.to_inner().to_be_bytes();
        let mut optimized_bytes = [0; 3];
        optimized_bytes.copy_from_slice(&bytes[1..=3]);
        NBytes::new(optimized_bytes)
    }
}

impl From<NBytes<[u8; 3]>> for PayloadFrameNum {
    fn from(nbytes: NBytes<[u8; 3]>) -> Self {
        let mut bytes = [0_u8; 4];
        bytes[1..=3].copy_from_slice(nbytes.as_ref());
        Self::from_u32_unchecked(u32::from_be_bytes(bytes))
    }
}

impl<F, OS> Skip<PayloadFrameNum> for wrap::Context<F, OS>
where
    F: PRP,
    OS: io::OStream,
{
    fn skip(&mut self, frame_num: PayloadFrameNum) -> Result<&mut Self> {
        // PayloadFrameNum validates bounds at creation, does not need to validate now
        self.skip(&NBytes::from(frame_num))
    }
}

impl<F, OS> Skip<&mut PayloadFrameNum> for unwrap::Context<F, OS>
where
    Self: for<'a> Skip<&'a mut NBytes<[u8; 3]>>,
{
    fn skip(&mut self, frame_num: &mut PayloadFrameNum) -> Result<&mut Self> {
        // PayloadFrameNum validates bounds at creation, does not need to validate now
        let mut bytes = NBytes::new([0_u8; 3]);
        self.skip(&mut bytes)?;
        *frame_num = bytes.into();
        Ok(self)
    }
}

impl Skip<PayloadFrameNum> for sizeof::Context {
    fn skip(&mut self, frame_num: PayloadFrameNum) -> Result<&mut Self> {
        // PayloadFrameNum validates bounds at creation, does not need to validate now
        self.skip(&NBytes::from(frame_num))
    }
}