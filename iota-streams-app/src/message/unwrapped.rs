use iota_streams_core::Result;

use super::*;
use iota_streams_core::{
    prelude::MutexGuard,
    sponge::{
        prp::PRP,
        spongos::Spongos,
    },
};
use iota_streams_ddml::link_store::LinkStore;

/// Result of wrapping the message.
pub struct UnwrappedMessage<F, Link, Content> {
    pub link: Link,
    pub pcf: PCF<Content>,
    pub(crate) spongos: Spongos<F>,
}

impl<F, Link, Content> UnwrappedMessage<F, Link, Content>
where
    F: PRP,
    Link: HasLink,
{
    /// Save link for the current unwrapped message and associated info into the store.
    pub fn commit<Store>(
        mut self,
        store: &mut MutexGuard<Store>,
        info: <Store as LinkStore<F, <Link as HasLink>::Rel>>::Info,
    ) -> Result<Content>
    where
        Store: LinkStore<F, <Link as HasLink>::Rel>,
    {
        self.spongos.commit();
        store.update(self.link.rel(), self.spongos, info)?;
        Ok(self.pcf.content)
    }
}
