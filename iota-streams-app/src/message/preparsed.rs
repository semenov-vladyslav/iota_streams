use iota_streams_core::Result;

use core::fmt;

use super::*;
use iota_streams_core::sponge::prp::PRP;
use iota_streams_ddml::command::unwrap;
use iota_streams_core::prelude::MutexGuard;

/// Message context preparsed for unwrapping.
pub struct PreparsedMessage<'a, F, Link: Default> {
    pub header: HDF<Link>,
    pub(crate) ctx: unwrap::Context<F, &'a [u8]>,
}

impl<'a, F, Link: Default + Clone> PreparsedMessage<'a, F, Link> {
    pub fn check_content_type(&self, content_type: u8) -> bool {
        self.content_type() == content_type
    }

    pub fn content_type(&self) -> u8 {
        self.header.get_content_type()
    }

    pub async fn unwrap<Store, Content>(
        mut self,
        store: &MutexGuard<'_, Store>,
        content: Content,
    ) -> Result<UnwrappedMessage<F, Link, Content>>
    where
        Content: ContentUnwrap<F, Store>,
        F: PRP,
        Store: Send + Sync,
    {
        let mut pcf = pcf::PCF::default_with_content(content);
        pcf.unwrap(store, &mut self.ctx).await?;
        // Discard what's left of `self.ctx.stream`
        Ok(UnwrappedMessage {
            link: self.header.link,
            pcf,
            spongos: self.ctx.spongos,
        })
    }
}

impl<'a, F, Link> Clone for PreparsedMessage<'a, F, Link>
where
    F: Clone,
    Link: Clone + Default,
{
    fn clone(&self) -> Self {
        Self {
            header: self.header.clone(),
            ctx: self.ctx.clone(),
        }
    }
}

impl<'a, F, Link> fmt::Debug for PreparsedMessage<'a, F, Link>
where
    Link: fmt::Debug + Default + Clone,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{header: {:?}, ctx: {:?}}}", self.header, "self.ctx")
    }
}
