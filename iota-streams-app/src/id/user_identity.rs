use crate::id::Identifier;
use crate::message::{ContentSign, ContentSizeof, ContentVerify};
use std::marker::PhantomData;
use iota_streams_core::{async_trait, err, Errors::{BadIdentifier, BadOneof, NoSignatureKeyPair}, prelude::Box, psk::{Psk, PskId}, prng, Result, sponge::prp::PRP};
use iota_streams_core_edsig::{
    key_exchange::x25519::{self, keypair_from_ed25519},
    signature::ed25519::{self, Keypair},
};
use iota_streams_ddml::{
    command::{sizeof, unwrap, wrap, Absorb, Ed25519, Commit, Squeeze},
    io,
    types::{External, HashSig, NBytes, Uint8, U64},
};

#[cfg(feature = "did")]
use identity::{
    core::{decode_b58, encode_b58},
    crypto::{JcsEd25519, Named, Signature, SignatureValue, Signer, Ed25519 as DIDEd25519},
    did::DID,
    iota::{Client, IotaDID}
};
#[cfg(feature = "did")]
use iota_streams_core::{
    Errors::{SignatureFailure, NotDIDUser, DIDMissing},
    prelude::{String, ToString, Vec},
    wrapped_err,
    WrappedError
};
#[cfg(feature = "did")]
use iota_streams_ddml::types::Bytes;
#[cfg(feature = "did")]
use crate::{
    id::{DID_CORE, DIDSize, DataWrapper},
    transport::{IdentityClient, tangle::client::Client as StreamsClient},
};
#[cfg(feature = "did")]
use futures::executor::block_on;

pub struct KeyPairs {
    sig: ed25519::Keypair,
    key_exchange: (x25519::StaticSecret, x25519::PublicKey),
}

pub enum Keys {
    Keypair(KeyPairs),
    Psk(Psk),
    #[cfg(feature = "did")]
    DID(DIDImpl)
}

#[cfg(feature = "did")]
pub struct DIDInfo {
    pub did: Option<IotaDID>,
    pub key_fragment: String,
    pub did_keypair: identity::crypto::KeyPair,
}


#[cfg(feature = "did")]
pub enum DIDImpl {
    //TODO: Add DID Account implementation
    PrivateKey(DIDInfo)
}

pub struct UserIdentity<F> {
    pub id: Identifier,
    keys: Keys,
    #[cfg(feature = "did")]
    client: Client,
    _phantom: PhantomData<F>
}

impl<F> Default for UserIdentity<F> {
    fn default() -> Self {
        //unwrap is fine because we are using default
        let sig_kp = ed25519::Keypair::from_bytes(&[0; 64]).unwrap();
        let ke_kp = x25519::keypair_from_ed25519(&sig_kp);

        UserIdentity {
            id: sig_kp.public.into(),
            keys: Keys::Keypair(KeyPairs {
                sig: sig_kp,
                key_exchange: ke_kp,
            }),
            #[cfg(feature = "did")]
            client: block_on(StreamsClient::default().to_identity_client()).unwrap(),
            _phantom: Default::default()
        }
    }
}

impl<F: PRP> UserIdentity<F> {
    pub async fn new(seed: &str) -> UserIdentity<F> {
        let nonce = "TANGLEUSERNONCE".as_bytes().to_vec();
        let prng = prng::from_seed::<F>("IOTA Streams Channels user sig keypair", seed);

        let sig_kp = ed25519::Keypair::generate(&mut prng::Rng::new(prng, nonce));
        let ke_kp = x25519::keypair_from_ed25519(&sig_kp);

        UserIdentity {
            id: sig_kp.public.into(),
            keys: Keys::Keypair(KeyPairs {
                sig: sig_kp,
                key_exchange: ke_kp,
            }),
            #[cfg(feature = "did")]
            client: StreamsClient::default().to_identity_client().await.unwrap(),
            _phantom: Default::default()
        }
    }

    pub async fn new_from_psk(pskid: PskId, psk: Psk) -> UserIdentity<F> {
        UserIdentity {
            id: pskid.into(),
            keys: Keys::Psk(psk),
            #[cfg(feature = "did")]
            client: StreamsClient::default().to_identity_client().await.unwrap(),
            _phantom: Default::default()
        }

    }

    #[cfg(feature = "did")]
    pub async fn new_with_did_private_key(did_info: DIDInfo, client: Client) -> Result<UserIdentity<F>> {
        let did = did_info.get_did()?;
        Ok(UserIdentity {
            id: (&did).into(),
            keys: Keys::DID(DIDImpl::PrivateKey(did_info)),
            client,
            _phantom: Default::default()
        })

    }

    #[cfg(feature = "did")]
    pub fn insert_did_client(&mut self, client: Client) {
        self.client = client;
    }
    //TODO: Implement new_from_account implementation

    /// Retrieve the key exchange keypair for encryption while sending packets
    pub fn get_ke_kp(&self) -> Result<(x25519::StaticSecret, x25519::PublicKey)> {
        match &self.keys {
            Keys::Keypair(keypairs) => {
                Ok(keypairs.key_exchange.clone())
            },
            Keys::Psk(_) => err(NoSignatureKeyPair),
            #[cfg(feature = "did")]
            Keys::DID(did) => match did{
                DIDImpl::PrivateKey(info) => Ok(info.get_ke_kp()),
                //TODO: Account implementation
            }
        }
    }

    /// Retrieve the signature secret key for user encryption while exporting and importing
    pub fn get_sig_sk(&self) -> Result<ed25519::SecretKey> {
        match &self.keys {
            Keys::Keypair(keypairs) => {
                let sk_bytes = keypairs.sig.secret.as_bytes();
                Ok(ed25519::SecretKey::from_bytes(sk_bytes)?)
            },
            Keys::Psk(_) => err(NoSignatureKeyPair),
            #[cfg(feature = "did")]
            Keys::DID(did) => match did{
                DIDImpl::PrivateKey(info) => {
                    let sig_kp = info.get_sig_kp();
                    Ok(ed25519::SecretKey::from_bytes(sig_kp.secret.as_bytes())?)
                }
                //TODO: Account implementation
            }
        }
    }

    /// Sign the prehashed bytes of a message for ownership authentication
    ///
    /// # Arguments
    /// * `data` - Wrapper containing the prehashed bytes of a message
    #[cfg(feature = "did")]
    async fn sign_data(&self, data: &mut DataWrapper) -> Result<Signature> {
        match &self.keys {
            Keys::DID(did_impl) => {
                match did_impl {
                    DIDImpl::PrivateKey(info) => {
                        let did = info.get_did()?;
                        let fragment = "#".to_string() + &info.key_fragment;
                        // Join the DID identifier with the key fragment of the verification method
                        let method = did.join(&fragment)?;
                        JcsEd25519::<DIDEd25519>::create_signature(data, method.to_string(), info.did_keypair.private().as_ref())?;
                    }
                }
                // Ensure that data signature was set
                match &data.signature {
                    Some(sig) => Ok(sig.clone()),
                    None => err(SignatureFailure),
                }
            }
            _ => err(NotDIDUser)
        }
    }

    /// Verify the sending signature of a message sent by another party in the Channel
    ///
    /// # Arguments
    /// * `did` - DID identifier
    /// * `data` - Wrapper containing the prehashed bytes of a message and the sender signature
    #[cfg(feature = "did")]
    async fn verify_data(&self, did: &IotaDID, data: DataWrapper) -> Result<bool> {
        let doc = self.client.read_document(did).await?;
        match doc.verify_data(&data) {
            Ok(_) => Ok(true),
            Err(e) => {
                println!("Verification Error: {:?}", e);
                Ok(false)
            }
        }
    }
}

#[cfg(feature = "did")]
impl DIDInfo {
    fn get_did(&self) -> Result<IotaDID> {
        match &self.did {
            Some(did) => Ok(did.clone()),
            None => err(DIDMissing)
        }
    }

    fn get_sig_kp(&self) -> ed25519::Keypair {
        let mut key_bytes = Vec::from(self.did_keypair.private().as_ref());
        key_bytes.extend(self.did_keypair.public().as_ref());
        ed25519::Keypair::from_bytes(&key_bytes).unwrap()
    }

    fn get_ke_kp(&self) -> (x25519::StaticSecret, x25519::PublicKey) {
        let kp = self.get_sig_kp();
        x25519::keypair_from_ed25519(&kp)
    }
}

impl<F> From<ed25519::Keypair> for UserIdentity<F> {
    fn from(kp: Keypair) -> Self {
        let ke_kp = keypair_from_ed25519(&kp);
        UserIdentity {
            id: Identifier::EdPubKey(kp.public.into()),
            keys: Keys::Keypair(KeyPairs {
                sig: kp,
                key_exchange: ke_kp,
            }),
            ..Default::default()
        }
    }
}

#[async_trait(?Send)]
impl<F: PRP> ContentSizeof<F> for UserIdentity<F> {
    async fn sizeof<'c>(&self, ctx: &'c mut sizeof::Context<F>) -> Result<&'c mut sizeof::Context<F>> {
        match &self.keys {
            Keys::Keypair(keys) => {
                ctx.absorb(Uint8(0))?;
                ctx.ed25519(&keys.sig, HashSig)?;
                return Ok(ctx);
            }
            Keys::Psk(_) => err(NoSignatureKeyPair),
            #[cfg(feature = "did")]
            Keys::DID(did_impl) => {
                match did_impl {
                    DIDImpl::PrivateKey(info) => {
                        if let Some(did) = &info.did {
                            ctx.absorb(Uint8(1))?;
                            ctx.absorb(<&NBytes<DIDSize>>::from(decode_b58(did.method_id())?.as_slice()))?;
                            ctx.absorb(&Bytes(info.key_fragment.as_bytes().to_vec()))?;

                        }
                    },
                    //TODO: Implement Account logic
                }
                // Absorb the size of a did based ed25519 signature
                let bytes = [0_u8; ed25519::SIGNATURE_LENGTH].to_vec();
                ctx.absorb(&Bytes(bytes))?;
                return Ok(ctx);
            }

        }
    }
}

#[async_trait(?Send)]
impl<F: PRP, OS: io::OStream> ContentSign<F, OS> for UserIdentity<F> {
    async fn sign<'c>(&self, ctx: &'c mut wrap::Context<F, OS>) -> Result<&'c mut wrap::Context<F, OS>> {
        match &self.keys {
            Keys::Keypair(keys) => {
                ctx.absorb(Uint8(0))?;
                let mut hash = External(NBytes::<U64>::default());
                ctx.commit()?.squeeze(&mut hash)?.ed25519(&keys.sig, &hash)?;
                Ok(ctx)
            }
            Keys::Psk(_) => err(NoSignatureKeyPair),
            #[cfg(feature = "did")]
            Keys::DID(did_impl) => {
                match did_impl {
                    DIDImpl::PrivateKey(info) => {
                        if let Some(did) = &info.did {
                            ctx.absorb(Uint8(1))?;
                            ctx.absorb(<&NBytes<DIDSize>>::from(decode_b58(did.method_id())?.as_slice()))?;
                            ctx.absorb(&Bytes(info.key_fragment.as_bytes().to_vec()))?;
                        }
                    }
                    //TODO: Implement Account logic
                }
                // Get the hash of the message
                let mut hash = External(NBytes::<U64>::default());
                ctx.commit()?.squeeze(&mut hash)?;
                // Append that hash to the additional context
                let mut prehashed = "IOTAStreams".as_bytes().to_vec();
                prehashed.extend_from_slice(&(hash.0).0);
                // Place hash in data wrapper and sign it
                let mut wrapper = DataWrapper {
                    data: prehashed,
                    signature: None,
                };

                match self.sign_data(&mut wrapper).await {
                    Ok(signature) => {
                        ctx.absorb(&Bytes(decode_b58(signature.value().as_str())?))?;
                        return Ok(ctx);
                    }
                    Err(e) => return Err(wrapped_err!(SignatureFailure, WrappedError(e))),
                }
            }
        }
    }
}

#[async_trait(?Send)]
impl<F: PRP, IS: io::IStream> ContentVerify<'_, F, IS> for UserIdentity<F> {
    async fn verify<'c>(&self, ctx: &'c mut unwrap::Context<F, IS>) -> Result<&'c mut unwrap::Context<F, IS>> {
        let mut oneof = Uint8(0);
        ctx.absorb(&mut oneof)?;
        match oneof.0 {
            0 => match &self.id {
                Identifier::EdPubKey(pub_key_wrap) => {
                    let mut hash = External(NBytes::<U64>::default());
                    ctx.commit()?.squeeze(&mut hash)?.ed25519(&pub_key_wrap.0, &hash)?;
                    Ok(ctx)
                }
                _ => err!(BadIdentifier)
            },
            #[cfg(feature = "did")]
            1 => {
                // Get DID method id
                let mut bytes = NBytes::<DIDSize>::default();
                ctx.absorb(&mut bytes)?;
                let did = did_from_bytes(&bytes.0)?;

                // Get key fragment
                let mut bytes = Bytes(Vec::new());
                ctx.absorb(&mut bytes)?;
                let fragment = "#".to_string() + &String::from_utf8(bytes.0)?;

                // Join fragment to did
                let did_url = did.join(fragment)?;
                // Get te hash of the message
                let mut hash = External(NBytes::<U64>::default());
                ctx.commit()?.squeeze(&mut hash)?;
                // Append that hash to the additional context
                let mut prehashed = "IOTAStreams".as_bytes().to_vec();
                prehashed.extend_from_slice(&(hash.0).0);

                let mut sig_bytes = Bytes(Vec::new());
                ctx.absorb(&mut sig_bytes)?;
                let mut signature = Signature::new(JcsEd25519::<DIDEd25519>::NAME, did_url.to_string());
                signature.set_value(SignatureValue::Signature(encode_b58(&sig_bytes.0)));

                // Place hash in data wrapper and verify it
                let wrapper = DataWrapper {
                    data: prehashed,
                    signature: Some(signature),
                };
                match self.verify_data(did_url.as_ref(), wrapper).await? {
                    true => Ok(ctx),
                    false => err(SignatureFailure),
                }
            },
            _ => err(BadOneof),
        }
    }
}

#[cfg(feature = "did")]
fn did_from_bytes(bytes: &[u8]) -> Result<IotaDID> {
    let mut did = DID_CORE.to_string();
    did.push_str(&encode_b58(bytes));
    Ok(IotaDID::parse(did)?)
}
