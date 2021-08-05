#[cfg(not(feature = "std"))]
pub use alloc::{
    boxed::{
        self,
        Box,
    },
    rc::{
        self,
        Rc,
    },
    string::{
        self,
        String,
        ToString,
    },
    sync::{
        self,
        Arc,
    },
    vec::{
        self,
        Vec,
    },
};

#[cfg(feature = "std")]
pub use std::{
    boxed::{
        self,
        Box,
    },
    rc::{
        self,
        Rc,
    },
    string::{
        self,
        String,
        ToString,
    },
    sync::{
        self,
        Arc,
    },
    vec::{
        self,
        Vec,
    },
};

pub use futures::lock::{Mutex, MutexGuard};

pub use hashbrown::{
    hash_map,
    hash_set,
    HashMap,
    HashSet,
};

// Reexport digest and generic_array and typenum crates here in order to simplify their import in other dependencies.
pub use digest::{
    self,
    generic_array::{
        self,
        typenum,
    },
};

pub use hex;
