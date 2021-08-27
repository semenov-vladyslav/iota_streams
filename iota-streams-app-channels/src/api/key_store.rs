use core::{
    convert::TryFrom,
    fmt,
};

use iota_streams_app::identifier::{
    Identifier,
    IdentifierInfoMut,
    IdentifierInfoRef,
    IdentifierKeyRef,
};
use iota_streams_core::{
    err,
    key_exchange::x25519,
    prelude::{
        HashMap,
        Vec,
    },
    psk::{
        Psk,
        PskId,
    },
    signature::ed25519,
    sponge::prp::PRP,
    wrapped_err,
    Errors::{
        BadIdentifier,
        KeyConversionFailure,
    },
    Result,
    WrappedError,
};

pub trait KeyStore<Info, F: PRP>: Default {
    fn filter<'a, Ids>(&'a self, ids: Ids) -> Vec<IdentifierKeyRef<'a>>
    where
        Ids: IntoIterator<Item = &'a Identifier>;
    fn keys(&self) -> Vec<IdentifierKeyRef>;
    fn iter(&self) -> Vec<IdentifierInfoRef<Info>>;
    fn iter_mut(&mut self) -> Vec<IdentifierInfoMut<Info>>;

    /// Retrieve the sequence state for a given publisher
    fn get(&self, id: &Identifier) -> Option<&Info>;
    fn get_mut(&mut self, id: &Identifier) -> Option<&mut Info>;
    fn get_ke_pk(&self, id: &Identifier) -> Option<&x25519::PublicKey>;
    fn get_psk(&self, id: &Identifier) -> Option<Psk>;
    fn contains(&self, id: &Identifier) -> bool;
    fn insert_cursor(&mut self, id: Identifier, info: Info) -> Result<()>;
    fn insert_psk(&mut self, id: Identifier, psk: Option<Psk>, info: Info) -> Result<()>;
    fn get_next_pskid(&self) -> Option<Identifier>;
}

pub struct KeyMap<Info> {
    /// Map from user identity -- ed25519 pk -- to
    /// a precalculated corresponding x25519 pk and some additional info.
    ke_pks: HashMap<ed25519::PublicKey, (x25519::PublicKey, Info)>,
    psks: HashMap<PskId, (Option<Psk>, Info)>,
}

impl<Info> KeyMap<Info> {
    pub fn new() -> Self {
        Self {
            ke_pks: HashMap::new(),
            psks: HashMap::new(),
        }
    }
}

impl<Info> Default for KeyMap<Info> {
    fn default() -> Self {
        Self::new()
    }
}

impl<Info, F: PRP> KeyStore<Info, F> for KeyMap<Info> {
    fn filter<'a, Ids>(&'a self, ids: Ids) -> Vec<IdentifierKeyRef<'a>>
    where
        Ids: IntoIterator<Item = &'a Identifier>,
    {
        ids.into_iter().filter_map(|id| match id {
            Identifier::EdPubKey(pk) => self
                .ke_pks
                .get_key_value(pk)
                .map(|(e, (x, _))| IdentifierKeyRef::EdPubKey(e, x)),
            Identifier::PskId(pskid) => self
                .psks
                .get_key_value(pskid)
                .filter(|(_, (x, _))| x.is_some())
                .map(|(e, (x, _))| IdentifierKeyRef::PskId(e, x)),
        })
        .collect()
    }

    fn get(&self, id: &Identifier) -> Option<&Info> {
        match id {
            Identifier::EdPubKey(pk) => self.ke_pks.get(pk).map(|(_x, i)| i),
            Identifier::PskId(pskid) => self.psks.get(pskid).map(|(_x, i)| i),
        }
    }
    fn get_mut(&mut self, id: &Identifier) -> Option<&mut Info> {
        match id {
            Identifier::EdPubKey(pk) => self.ke_pks.get_mut(pk).map(|(_x, i)| i),
            Identifier::PskId(pskid) => self.psks.get_mut(pskid).map(|(_x, i)| i),
        }
    }
    fn get_ke_pk(&self, id: &Identifier) -> Option<&x25519::PublicKey> {
        match id {
            Identifier::EdPubKey(pk) => self.ke_pks.get(pk).map(|(x, _i)| x),
            _ => None,
        }
    }

    fn get_psk(&self, id: &Identifier) -> Option<Psk> {
        match id {
            Identifier::PskId(pskid) => match self.psks.get(pskid).map(|(x, _i)| *x) {
                Some(psk) => psk,
                None => None,
            },
            _ => None,
        }
    }

    fn get_next_pskid(&self) -> Option<Identifier> {
        let mut iter = self.psks.iter();
        loop {
            match iter.next() {
                Some((e, (x, _i))) => {
                    if x.is_some() {
                        return Some(Identifier::PskId(*e));
                    }
                }
                None => return None,
            }
        }
    }

    fn contains(&self, id: &Identifier) -> bool {
        match id {
            Identifier::EdPubKey(pk) => self.ke_pks.contains_key(pk),
            Identifier::PskId(pskid) => self.psks.contains_key(pskid),
        }
    }

    fn insert_cursor(&mut self, id: Identifier, info: Info) -> Result<()> {
        match id {
            Identifier::EdPubKey(pk) => {
                let xpk =
                    x25519::PublicKey::try_from(&pk).map_err(|e| wrapped_err(KeyConversionFailure, WrappedError(e)))?;
                self.ke_pks.insert(pk, (xpk, info));
                Ok(())
            }
            Identifier::PskId(pskid) => {
                self.psks.insert(pskid, (None, info));
                Ok(())
            }
        }
    }

    fn insert_psk(&mut self, id: Identifier, psk: Option<Psk>, info: Info) -> Result<()> {
        match id {
            Identifier::PskId(pskid) => {
                self.psks.insert(pskid, (psk, info));
                Ok(())
            }
            _ => err(BadIdentifier),
        }
    }

    fn keys(&self) -> Vec<IdentifierKeyRef> {
        let mut keys: Vec<IdentifierKeyRef> = self
            .ke_pks
            .iter()
            .map(|(k, (x, _i))| IdentifierKeyRef::EdPubKey(k, x))
            .collect();

        let psks: Vec<IdentifierKeyRef> = self
            .psks
            .iter()
            .filter_map(|(k, (x, _i))| x.map(|_psk| IdentifierKeyRef::PskId(k, x)))
            .collect();

        keys.extend(psks);
        keys
    }

    fn iter(&self) -> Vec<IdentifierInfoRef<Info>> {
        let mut keys: Vec<IdentifierInfoRef<Info>> = self
            .ke_pks
            .iter()
            .map(|(k, (_x, i))| IdentifierInfoRef::EdPubKey(k, i))
            .collect();

        let psks: Vec<IdentifierInfoRef<Info>> = self
            .psks
            .iter()
            .map(|(k, (_x, i))| IdentifierInfoRef::PskId(k, i))
            .collect();

        keys.extend(psks);
        keys
    }
    fn iter_mut(&mut self) -> Vec<IdentifierInfoMut<Info>> {
        let mut keys: Vec<IdentifierInfoMut<Info>> = self
            .ke_pks
            .iter_mut()
            .map(|(k, (_x, i))| IdentifierInfoMut::EdPubKey(k, i))
            .collect();

        let psks: Vec<IdentifierInfoMut<Info>> = self
            .psks
            .iter_mut()
            .map(|(k, (_x, i))| IdentifierInfoMut::PskId(k, i))
            .collect();

        keys.extend(psks);
        keys
    }
}

impl<Info: fmt::Display> fmt::Display for KeyMap<Info> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (k, (_x, i)) in self.ke_pks.iter() {
            writeln!(f, "    <{}> => {}", hex::encode(&k.as_slice()), i)?;
        }
        for (k, (_x, i)) in self.psks.iter() {
            writeln!(f, "    <{}> => {}", hex::encode(&k.as_slice()), i)?;
        }
        Ok(())
    }
}
