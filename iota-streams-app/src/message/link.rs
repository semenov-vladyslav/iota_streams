use core::fmt;

use iota_streams_core::{
    prelude::Vec,
    signature::ed25519,
    Result,
};

use super::hdf::HDF;
use crate::identifier::Identifier;
use iota_streams_ddml::types::Bytes;

/// Type of "absolute" links. For http it's the absolute URL.
pub trait HasLink: Sized + Default + Clone + Eq {
    /// Type of "base" links. For http it's domain name.
    type Base: Default + Clone;

    /// Get base part of the link.
    fn base(&self) -> &Self::Base;

    /// Type of "relative" links. For http it's URL path.
    type Rel: Default + Clone;

    /// Get relative part of the link.
    fn rel(&self) -> &Self::Rel;

    /// Construct absolute link from base and relative parts.
    fn from_base_rel(base: &Self::Base, rel: &Self::Rel) -> Self;

    /// Represent absolute link as bytes
    fn to_bytes(&self) -> Vec<u8>;

    /// Get link from bytes
    fn from_bytes(bytes: &[u8]) -> Self;
}

/// Represents an input state for message identifier generation.
/// Contains an Address and sequencing states.
#[derive(Clone, Default)]
pub struct Cursor<Link> {
    pub link: Link,
    pub branch_no: u32,
    pub seq_no: u32,
}

impl<Link> Cursor<Link> {
    pub fn new(link: Link) -> Self {
        Self {
            link,
            branch_no: 0,
            seq_no: 0,
        }
    }
    pub fn new_at(link: Link, branch_no: u32, seq_no: u32) -> Self {
        Self {
            link,
            branch_no,
            seq_no,
        }
    }
}

impl<Link> Cursor<Link> {
    pub fn next_branch(&mut self) {
        self.branch_no += 1;
        self.seq_no = 0;
    }

    pub fn next_seq(&mut self) {
        self.seq_no += 1;
    }

    pub fn get_seq_num(&self) -> u64 {
        (self.branch_no as u64) << 32 | (self.seq_no as u64)
    }

    pub fn set_seq_num(&mut self, seq_num: u64) {
        self.seq_no = seq_num as u32;
        self.branch_no = (seq_num >> 32) as u32;
    }

    pub fn as_ref(&self) -> Cursor<&Link> {
        Cursor {
            link: &self.link,
            branch_no: self.branch_no,
            seq_no: self.seq_no,
        }
    }

    pub fn as_mut(&mut self) -> Cursor<&mut Link> {
        Cursor {
            link: &mut self.link,
            branch_no: self.branch_no,
            seq_no: self.seq_no,
        }
    }
}

impl<Link: fmt::Display> fmt::Display for Cursor<Link> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{},{}:{}>", self.link, self.branch_no, self.seq_no)
    }
}

impl<Link: fmt::Debug> fmt::Debug for Cursor<Link> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{:?},{}:{}>", self.link, self.branch_no, self.seq_no)
    }
}

/// Abstraction-helper to generate message links.
pub trait LinkGenerator<Link: HasLink>: Default {
    /// Used by Author to generate a new application instance: channels address and announcement message identifier
    fn gen(&mut self, pk: &ed25519::PublicKey, idx: u64);

    /// Used by Author to get announcement message id, it's just stored internally by link generator
    fn get(&self) -> Link;

    /// Used by Subscriber to initialize link generator with the same state as Author
    fn reset(&mut self, seed: Link);

    /// Used by users to pseudo-randomly generate a new uniform message link from a cursor
    fn uniform_link_from(&self, cursor: Cursor<&<Link as HasLink>::Rel>) -> Link;

    /// Used by users to pseudo-randomly generate a new message link from a cursor
    fn link_from(&self, id: &Identifier, cursor: Cursor<&<Link as HasLink>::Rel>) -> Link;

    /// Derive a new link and construct a header with given content type.
    fn uniform_header_from(
        &self,
        id: &Identifier,
        cursor: Cursor<&<Link as HasLink>::Rel>,
        content_type: u8,
        payload_length: usize,
        seq_num: u64,
        previous_msg_link: &Link,
    ) -> Result<HDF<Link>> {
        HDF::new_with_fields(
            self.uniform_link_from(cursor),
            Bytes(previous_msg_link.to_bytes()),
            content_type,
            payload_length,
            seq_num,
            id,
        )
    }

    /// Derive a new link and construct a header with given content type.
    fn header_from(
        &self,
        id: &Identifier,
        cursor: Cursor<&<Link as HasLink>::Rel>,
        content_type: u8,
        payload_length: usize,
        seq_num: u64,
        previous_msg_link: &Link,
    ) -> Result<HDF<Link>> {
        HDF::new_with_fields(
            self.link_from(id, cursor),
            Bytes(previous_msg_link.to_bytes()),
            content_type,
            payload_length,
            seq_num,
            id,
        )
    }
}

pub trait LinkedMessage<Link> {
    fn link(&self) -> &Link;
    fn prev_link(&self) -> &Link;
}
