use core::fmt;

use iota_streams_app::identifier::Identifier;
use iota_streams_core::{
    err,
    prelude::{
        HashMap,
        Vec,
    },
    psk::Psk,
    sponge::prp::PRP,
    Errors::BadIdentifier,
    Result,
};
use iota_streams_core_edsig::key_exchange::x25519;

pub trait KeyStore<Info, F: PRP>: Default {
    fn filter<'a, I>(&self, ids: I) -> Vec<(&Identifier, Vec<u8>)>
    where
        I: IntoIterator<Item = &'a Identifier>;

    /// Retrieve the sequence state for a given publisher
    fn get(&self, id: &Identifier) -> Option<&Info>;
    fn get_mut(&mut self, id: &Identifier) -> Option<&mut Info>;
    fn get_ke_pk(&self, id: &Identifier) -> Option<&x25519::PublicKey>;
    fn get_psk(&self, id: &Identifier) -> Option<Psk>;
    fn contains(&self, id: &Identifier) -> bool;
    fn insert_cursor(&mut self, id: Identifier, info: Info) -> Result<()>;
    fn insert_psk(&mut self, id: Identifier, psk: Option<Psk>, info: Info) -> Result<()>;
    fn get_next_pskid(&self) -> Option<&Identifier>;
    fn keys(&self) -> Vec<(&Identifier, Vec<u8>)>;
    fn iter(&self) -> Vec<(&Identifier, &Info)>;
    fn iter_mut(&mut self) -> Vec<(&Identifier, &mut Info)>;
}

pub struct KeyMap<Info> {
    /// Map from user identity -- ed25519 pk -- to
    /// a precalculated corresponding x25519 pk and some additional info.
    ke_pks: HashMap<Identifier, (x25519::PublicKey, Info)>,
    psks: HashMap<Identifier, (Option<Psk>, Info)>,
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
    fn filter<'a, I>(&self, ids: I) -> Vec<(&Identifier, Vec<u8>)>
    where
        I: IntoIterator<Item = &'a Identifier>,
    {
        ids.into_iter()
            .filter_map(|id| match &id {
                Identifier::EdPubKey(_id) => self
                    .ke_pks
                    .get_key_value(id)
                    .map(|(e, (x, _))| (e, x.as_bytes().to_vec())),
                Identifier::PskId(_id) => self
                    .psks
                    .get_key_value(id)
                    .map(|(e, (x, _))| x.map(|xx| (e, xx.to_vec())))
                    .flatten(),
            })
            .collect()
    }

    fn get(&self, id: &Identifier) -> Option<&Info> {
        match id {
            Identifier::EdPubKey(_pk) => self.ke_pks.get(id).map(|(_x, i)| i),
            Identifier::PskId(_id) => self.psks.get(id).map(|(_x, i)| i),
        }
    }
    fn get_mut(&mut self, id: &Identifier) -> Option<&mut Info> {
        match id {
            Identifier::EdPubKey(_pk) => self.ke_pks.get_mut(id).map(|(_x, i)| i),
            Identifier::PskId(_id) => self.psks.get_mut(id).map(|(_x, i)| i),
        }
    }
    fn get_ke_pk(&self, id: &Identifier) -> Option<&x25519::PublicKey> {
        match id {
            Identifier::EdPubKey(_pk) => self.ke_pks.get(id).map(|(x, _i)| x),
            _ => None,
        }
    }

    fn get_psk(&self, id: &Identifier) -> Option<Psk> {
        match id {
            Identifier::PskId(_id) => match self.psks.get(id).map(|(x, _i)| *x) {
                Some(psk) => psk,
                None => None,
            },
            _ => None,
        }
    }

    fn get_next_pskid(&self) -> Option<&Identifier> {
        let mut iter = self.psks.iter();
        loop {
            match iter.next() {
                Some((e, (x, _i))) => {
                    if x.is_some() {
                        return Some(e);
                    }
                }
                None => return None,
            }
        }
    }

    fn contains(&self, id: &Identifier) -> bool {
        self.ke_pks.contains_key(id) || self.psks.contains_key(id)
    }

    fn insert_cursor(&mut self, id: Identifier, info: Info) -> Result<()> {
        match &id {
            Identifier::EdPubKey(pk) => {
                let store_id = x25519::public_from_ed25519(&pk.0)?;
                self.ke_pks.insert(id, (store_id, info));
                Ok(())
            }
            Identifier::PskId(_id) => {
                self.psks.insert(id, (None, info));
                Ok(())
            }
        }
    }

    fn insert_psk(&mut self, id: Identifier, psk: Option<Psk>, info: Info) -> Result<()> {
        match &id {
            Identifier::PskId(_id) => {
                self.psks.insert(id, (psk, info));
                Ok(())
            }
            _ => err(BadIdentifier),
        }
    }

    fn keys(&self) -> Vec<(&Identifier, Vec<u8>)> {
        let mut keys: Vec<(&Identifier, Vec<u8>)> = self
            .ke_pks
            .iter()
            .map(|(k, (x, _i))| (k, x.as_bytes().to_vec()))
            .collect();

        let psks: Vec<(&Identifier, Vec<u8>)> = self
            .psks
            .iter()
            .filter_map(|(k, (x, _i))| x.map(|x| (k, x.to_vec())))
            .collect();

        keys.extend(psks);
        keys
    }

    fn iter(&self) -> Vec<(&Identifier, &Info)> {
        let mut keys: Vec<(&Identifier, &Info)> = self.ke_pks.iter().map(|(k, (_x, i))| (k, i)).collect();

        let psks: Vec<(&Identifier, &Info)> = self.psks.iter().map(|(k, (_x, i))| (k, i)).collect();

        keys.extend(psks);
        keys
    }
    fn iter_mut(&mut self) -> Vec<(&Identifier, &mut Info)> {
        let mut ke_pks: Vec<(&Identifier, &mut Info)> = self.ke_pks.iter_mut().map(|(k, (_x, i))| (k, i)).collect();

        let psks: Vec<(&Identifier, &mut Info)> = self.psks.iter_mut().map(|(k, (_x, i))| (k, i)).collect();

        ke_pks.extend(psks);
        ke_pks
    }
}

impl<Info: fmt::Display> fmt::Display for KeyMap<Info> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (k, (_x, i)) in self.ke_pks.iter() {
            writeln!(f, "    <{}> => {}", hex::encode(&k.to_bytes()), i)?;
        }
        for (k, (_x, i)) in self.psks.iter() {
            writeln!(f, "    <{}> => {}", hex::encode(&k.to_bytes()), i)?;
        }
        Ok(())
    }
}
