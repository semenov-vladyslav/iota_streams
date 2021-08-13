use core::hash;
use iota_streams_core::Result;

use core::fmt::Display;
use iota_streams_core::{
    err,
    prelude::{
        string::ToString,
        HashMap,
        Vec,
    },
    sponge::{
        prp::{
            Inner,
            PRP,
        },
        spongos::Spongos,
    },
    try_or,
    Errors::{
        GenericLinkNotFound,
        MessageLinkNotFoundInTangle,
    },
};

/// The `link` type is generic and transport-specific. Links can be address+tag pair
/// when messages are published in the Tangle. Or links can be a URL when HTTP is used.
/// Or links can be a message sequence number in a stream/socket.
pub trait LinkStore<F, Link>: Send + Sync {
    /// Additional data associated with the current message link/spongos state.
    /// This type is implementation specific, meaning different configurations
    /// of a Streams Application can use different Info types.
    type Info;

    /// Lookup link in the store and return spongos state and associated info.
    fn lookup(&self, _link: &Link) -> Result<(Spongos<F>, Self::Info)> {
        err!(GenericLinkNotFound)
    }

    /// Put link into the store together with spongos state and associated info.
    ///
    /// Implementations should handle the case where link is already in the store,
    /// but spongos state is different. Such situation can indicate an attack,
    /// integrity violation (how exactly?), or internal error.
    ///
    /// Overwriting the spongos state means "forgetting the old and accepting the new".
    ///
    /// Not updating the spongos state means immutability -- "the first one makes the history".
    fn update(&mut self, link: &Link, spongos: Spongos<F>, info: Self::Info) -> Result<()>;

    fn insert(&mut self, link: &Link, spongos: Inner<F>, info: Self::Info) -> Result<()>
    where
        F: PRP;

    /// Remove link and associated info from the store.
    fn erase(&mut self, _link: &Link) {}

    fn iter(&self) -> Vec<(&Link, &(Inner<F>, Self::Info))>
    where
        F: PRP;
}

/// Empty "dummy" link store that stores no links.
#[derive(Copy, Clone, Debug)]
pub struct EmptyLinkStore<F, Link, Info>(core::marker::PhantomData<(F, Link, Info)>);

impl<F, Link, Info> Default for EmptyLinkStore<F, Link, Info> {
    fn default() -> Self {
        Self(core::marker::PhantomData)
    }
}

impl<F, Link, Info> LinkStore<F, Link> for EmptyLinkStore<F, Link, Info>
where
    F: Send + Sync,
    Link: Send + Sync,
    Info: Send + Sync,
{
    type Info = Info;
    fn update(&mut self, _link: &Link, _spongos: Spongos<F>, _info: Self::Info) -> Result<()> {
        Ok(())
    }
    fn insert(&mut self, _link: &Link, _spongos: Inner<F>, _info: Self::Info) -> Result<()>
    where
        F: PRP,
    {
        Ok(())
    }
    fn iter(&self) -> Vec<(&Link, &(Inner<F>, Self::Info))>
    where
        F: PRP,
    {
        Vec::new()
    }
}

/// Link store that contains a single link.
/// This link store can be used in Streams Applications supporting a list-like "thread"
/// of messages without access to the history as the link to the last message is stored.
#[derive(Clone, Default)]
pub struct SingleLinkStore<F: PRP, Link, Info>(Link, (Inner<F>, Info));

impl<F: PRP, Link, Info> SingleLinkStore<F, Link, Info> {
    pub fn link(&self) -> &Link {
        &self.0
    }
    pub fn spongos(&self) -> &Inner<F> {
        &(self.1).0
    }
    pub fn info(&self) -> &Info {
        &(self.1).1
    }
}

impl<F: PRP, Link, Info> LinkStore<F, Link> for SingleLinkStore<F, Link, Info>
where
    Link: Clone + Eq + Display + Send + Sync,
    Info: Clone + Send + Sync,
{
    type Info = Info;
    fn lookup(&self, link: &Link) -> Result<(Spongos<F>, Self::Info)> {
        try_or!(self.link() == link, MessageLinkNotFoundInTangle(link.to_string()))?;
        Ok((self.spongos().into(), self.info().clone()))
    }
    fn update(&mut self, link: &Link, spongos: Spongos<F>, info: Self::Info) -> Result<()> {
        self.0 = link.clone();
        self.1 = (spongos.into(), info);
        Ok(())
    }
    fn insert(&mut self, link: &Link, spongos: Inner<F>, info: Self::Info) -> Result<()> {
        self.0 = link.clone();
        self.1 = (spongos, info);
        Ok(())
    }
    fn erase(&mut self, _link: &Link) {
        // Can't really erase link.
    }
    fn iter(&self) -> Vec<(&Link, &(Inner<F>, Self::Info))> {
        vec![(&self.0, &self.1)]
    }
}

pub struct DefaultLinkStore<F: PRP, Link, Info> {
    map: HashMap<Link, (Inner<F>, Info)>,
    _phantom: core::marker::PhantomData<F>,
}

impl<F: PRP, Link, Info> Default for DefaultLinkStore<F, Link, Info>
where
    Link: Eq + hash::Hash + Send + Sync,
    Info: Send + Sync,
{
    fn default() -> Self {
        Self {
            map: HashMap::new(),
            _phantom: core::marker::PhantomData,
        }
    }
}

impl<F: PRP, Link, Info> LinkStore<F, Link> for DefaultLinkStore<F, Link, Info>
where
    Link: Eq + hash::Hash + Clone + Display + Send + Sync,
    Info: Clone + Send + Sync,
{
    type Info = Info;

    /// Add info for the link.
    fn lookup(&self, link: &Link) -> Result<(Spongos<F>, Info)> {
        match self.map.get(link) {
            Some((inner, info)) => Ok((inner.into(), info.clone())),
            None => err!(MessageLinkNotFoundInTangle(link.to_string())),
        }
    }

    /// Try to retrieve info for the link.
    fn update(&mut self, link: &Link, spongos: Spongos<F>, info: Info) -> Result<()> {
        let inner = spongos.to_inner()?;
        self.map.insert(link.clone(), (inner, info));
        Ok(())
    }

    fn insert(&mut self, link: &Link, inner: Inner<F>, info: Self::Info) -> Result<()> {
        self.map.insert(link.clone(), (inner, info));
        Ok(())
    }

    /// Remove info for the link.
    fn erase(&mut self, link: &Link) {
        self.map.remove(link);
    }

    fn iter(&self) -> Vec<(&Link, &(Inner<F>, Self::Info))> {
        self.map.iter().collect()
    }
}
