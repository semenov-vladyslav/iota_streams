use core::fmt;
use iota_streams_core::Result;

use super::*;
use iota_streams_core::{
    prelude::Vec,
    sponge::prp::PRP,
};
use iota_streams_ddml::{
    command::unwrap,
    link_store::EmptyLinkStore,
    types::*,
};

/// Binary Message body with information of how to parse it.
pub struct BinaryBody<F> {
    pub bytes: Vec<u8>,

    pub(crate) _phantom: core::marker::PhantomData<F>,
}

/// Binary network Message representation.
pub type BinaryMessage<F, AbsLink> = GenericMessage<AbsLink, BinaryBody<F>>;

impl<F> PartialEq for BinaryBody<F> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes.eq(&other.bytes)
    }
}

impl<F> fmt::Debug for BinaryBody<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // TODO: first 10 bytes of body is average HDF
        write!(f, "{}", hex::encode(&self.bytes[..10]))
    }
}

impl<F> fmt::Display for BinaryBody<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.bytes[..]))
    }
}

impl<F> Clone for BinaryBody<F> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes.clone(),
            _phantom: core::marker::PhantomData,
        }
    }
}

impl<F> From<Vec<u8>> for BinaryBody<F> {
    fn from(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            _phantom: core::marker::PhantomData,
        }
    }
}

impl<F, Link> BinaryMessage<F, Link>
where
    F: PRP,
    Link: Clone + AbsorbExternalFallback<F> + HasLink + std::fmt::Debug,
{
    pub async fn parse_header(&self) -> Result<PreparsedMessage<'_, F, Link>> {
        let mut ctx = unwrap::Context::new(&self.body.bytes[..]);
        let mut header =
            HDF::<Link>::new(self.link().clone()).with_previous_msg_link(Bytes(self.prev_link().to_bytes()));
        let store = EmptyLinkStore::<F, Link, ()>::default();
        header.unwrap(&store, &mut ctx).await?;

        Ok(PreparsedMessage { header, ctx })
    }
}
