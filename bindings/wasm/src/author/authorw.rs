use core::convert::TryInto as _;
use wasm_bindgen::prelude::*;

use crate::{
    types::{
        PskIds as PskIdsW,
        PublicKeys as PublicKeysW,
        *,
    },
    user::userw::*,
};
use js_sys::Array;

use core::cell::RefCell;

use iota_streams::app::identifier::Identifier;
/// Streams imports
use iota_streams::{
    app::transport::{
        tangle::client::Client as ApiClient,
        TransportOptions,
    },
    app_channels::api::{
        psk_from_seed,
        pskid_from_psk,
        tangle::{
            Address as ApiAddress,
            Author as ApiAuthor,
        },
    },
    core::{
        prelude::{
            Rc,
            String,
            ToString,
        },
        psk::pskid_to_hex_string,
    },
    ddml::types::*,
};

#[wasm_bindgen]
pub struct Author {
    author: Rc<RefCell<ApiAuthor<ClientWrap>>>,
}

#[wasm_bindgen]
impl Author {
    #[wasm_bindgen(constructor)]
    pub fn new(seed: String, options: SendOptions, implementation: ChannelType) -> Author {
        let mut client = ApiClient::new_from_url(&options.url());
        client.set_send_options(options.into());
        let transport = Rc::new(RefCell::new(client));

        let author = Rc::new(RefCell::new(ApiAuthor::new(&seed, implementation.into(), transport)));
        Author { author }
    }

    pub fn from_client(client: Client, seed: String, implementation: ChannelType) -> Author {
        let author = Rc::new(RefCell::new(ApiAuthor::new(
            &seed,
            implementation.into(),
            client.to_inner(),
        )));
        Author { author }
    }

    #[wasm_bindgen(catch)]
    pub fn import(client: Client, bytes: Vec<u8>, password: &str) -> Result<Author> {
        ApiAuthor::import(&bytes, password, client.to_inner()).map_or_else(
            |err| Err(JsValue::from_str(&err.to_string())),
            |v| {
                Ok(Author {
                    author: Rc::new(RefCell::new(v)),
                })
            },
        )
    }

    #[wasm_bindgen(catch)]
    pub fn export(&self, password: &str) -> Result<Vec<u8>> {
        self.author
            .borrow_mut()
            .export(password)
            .map_or_else(|err| Err(JsValue::from_str(&err.to_string())), Ok)
    }

    pub fn clone(&self) -> Author {
        Author {
            author: self.author.clone(),
        }
    }

    #[wasm_bindgen(catch)]
    pub fn channel_address(&self) -> Result<String> {
        to_result(
            self.author
                .borrow_mut()
                .channel_address()
                .map(|addr| addr.to_string())
                .ok_or("channel not created"),
        )
    }

    #[wasm_bindgen(catch)]
    pub fn is_multi_branching(&self) -> Result<bool> {
        Ok(self.author.borrow_mut().is_multi_branching())
    }

    #[wasm_bindgen(catch)]
    pub fn get_client(&self) -> Client {
        Client(self.author.borrow_mut().get_transport().clone())
    }

    #[wasm_bindgen(catch)]
    pub fn store_psk(&self, psk_seed_str: String) -> Result<String> {
        let psk = psk_from_seed(psk_seed_str.as_bytes());
        let pskid = pskid_from_psk(&psk);
        let pskid_str = pskid_to_hex_string(&pskid);
        to_result(self.author.borrow_mut().store_psk(pskid, psk))?;
        Ok(pskid_str)
    }

    #[wasm_bindgen(catch)]
    pub fn get_public_key(&self) -> Result<String> {
        Ok(public_key_to_string(self.author.borrow_mut().get_public_key()))
    }

    #[wasm_bindgen(catch)]
    pub async fn send_announce(self) -> Result<UserResponse> {
        self.author.borrow_mut().send_announce().await.map_or_else(
            |err| Err(JsValue::from_str(&err.to_string())),
            |addr| Ok(UserResponse::new(Address::from_string(addr.to_string()), None, None)),
        )
    }

    #[wasm_bindgen(catch)]
    pub async fn send_keyload_for_everyone(self, link: Address) -> Result<UserResponse> {
        self.author
            .borrow_mut()
            .send_keyload_for_everyone(
                &link
                    .try_into()
                    .map_or_else(|_err| ApiAddress::default(), |addr: ApiAddress| addr),
            )
            .await
            .map_or_else(
                |err| Err(JsValue::from_str(&err.to_string())),
                |(link, seq_link)| {
                    if let Some(seq_link) = seq_link {
                        Ok(UserResponse::from_strings(
                            link.to_string(),
                            Some(seq_link.to_string()),
                            None,
                        ))
                    } else {
                        Ok(UserResponse::from_strings(link.to_string(), None, None))
                    }
                },
            )
    }

    #[wasm_bindgen(catch)]
    pub async fn send_keyload(self, link: Address, psk_ids: PskIdsW, sig_pks: PublicKeysW) -> Result<UserResponse> {
        let pks = sig_pks.pks.into_iter().map(Into::<Identifier>::into);
        let psks = psk_ids.ids.into_iter().map(Into::<Identifier>::into);
        let identifiers: Vec<Identifier> = pks.chain(psks).collect();
        self.author
            .borrow_mut()
            .send_keyload(
                &link
                    .try_into()
                    .map_or_else(|_err| ApiAddress::default(), |addr: ApiAddress| addr),
                &identifiers,
            )
            .await
            .map_or_else(
                |err| Err(JsValue::from_str(&err.to_string())),
                |(link, seq_link)| {
                    if let Some(seq_link) = seq_link {
                        Ok(UserResponse::from_strings(
                            link.to_string(),
                            Some(seq_link.to_string()),
                            None,
                        ))
                    } else {
                        Ok(UserResponse::from_strings(link.to_string(), None, None))
                    }
                },
            )
    }

    #[wasm_bindgen(catch)]
    pub async fn send_tagged_packet(
        self,
        link: Address,
        public_payload: Vec<u8>,
        masked_payload: Vec<u8>,
    ) -> Result<UserResponse> {
        self.author
            .borrow_mut()
            .send_tagged_packet(
                &link
                    .try_into()
                    .map_or_else(|_err| ApiAddress::default(), |addr: ApiAddress| addr),
                &Bytes(public_payload.clone()),
                &Bytes(masked_payload.clone()),
            )
            .await
            .map_or_else(
                |err| Err(JsValue::from_str(&err.to_string())),
                |(link, seq_link)| {
                    if let Some(seq_link) = seq_link {
                        Ok(UserResponse::from_strings(
                            link.to_string(),
                            Some(seq_link.to_string()),
                            None,
                        ))
                    } else {
                        Ok(UserResponse::from_strings(link.to_string(), None, None))
                    }
                },
            )
    }

    #[wasm_bindgen(catch)]
    pub async fn send_signed_packet(
        self,
        link: Address,
        public_payload: Vec<u8>,
        masked_payload: Vec<u8>,
    ) -> Result<UserResponse> {
        self.author
            .borrow_mut()
            .send_signed_packet(
                &link
                    .try_into()
                    .map_or_else(|_err| ApiAddress::default(), |addr: ApiAddress| addr),
                &Bytes(public_payload),
                &Bytes(masked_payload),
            )
            .await
            .map_or_else(
                |err| Err(JsValue::from_str(&err.to_string())),
                |(link, seq_link)| {
                    if let Some(seq_link) = seq_link {
                        Ok(UserResponse::from_strings(
                            link.to_string(),
                            Some(seq_link.to_string()),
                            None,
                        ))
                    } else {
                        Ok(UserResponse::from_strings(link.to_string(), None, None))
                    }
                },
            )
    }

    #[wasm_bindgen(catch)]
    pub async fn receive_subscribe(self, link_to: Address) -> Result<()> {
        self.author
            .borrow_mut()
            .receive_subscribe(
                &link_to
                    .try_into()
                    .map_or_else(|_err| ApiAddress::default(), |addr| addr),
            )
            .await
            .map_or_else(|err| Err(JsValue::from_str(&err.to_string())), |_| Ok(()))
    }

    #[wasm_bindgen(catch)]
    pub async fn receive_tagged_packet(self, link: Address) -> Result<UserResponse> {
        self.author
            .borrow_mut()
            .receive_tagged_packet(
                &link
                    .copy()
                    .try_into()
                    .map_or_else(|_err| ApiAddress::default(), |addr| addr),
            )
            .await
            .map_or_else(
                |err| Err(JsValue::from_str(&err.to_string())),
                |(pub_bytes, masked_bytes)| {
                    Ok(UserResponse::new(
                        link,
                        None,
                        Some(Message::new(None, pub_bytes.0, masked_bytes.0)),
                    ))
                },
            )
    }

    #[wasm_bindgen(catch)]
    pub async fn receive_signed_packet(self, link: Address) -> Result<UserResponse> {
        self.author
            .borrow_mut()
            .receive_signed_packet(
                &link
                    .copy()
                    .try_into()
                    .map_or_else(|_err| ApiAddress::default(), |addr| addr),
            )
            .await
            .map_or_else(
                |err| Err(JsValue::from_str(&err.to_string())),
                |(pk, pub_bytes, masked_bytes)| {
                    Ok(UserResponse::new(
                        link,
                        None,
                        Some(Message::new(
                            Some(public_key_to_string(&pk)),
                            pub_bytes.0,
                            masked_bytes.0,
                        )),
                    ))
                },
            )
    }

    #[wasm_bindgen(catch)]
    pub async fn receive_sequence(self, link: Address) -> Result<Address> {
        self.author
            .borrow_mut()
            .receive_sequence(&link.try_into().map_or_else(|_err| ApiAddress::default(), |addr| addr))
            .await
            .map_or_else(
                |err| Err(JsValue::from_str(&err.to_string())),
                |address| Ok(Address::from_string(address.to_string())),
            )
    }

    #[wasm_bindgen(catch)]
    pub async fn receive_msg(self, link: Address) -> Result<UserResponse> {
        self.author
            .borrow_mut()
            .receive_msg(&link.try_into().map_or_else(|_err| ApiAddress::default(), |addr| addr))
            .await
            .map_or_else(
                |err| Err(JsValue::from_str(&err.to_string())),
                |msg| {
                    let msgs = vec![msg];
                    let responses = get_message_contents(msgs);
                    Ok(responses[0].copy())
                },
            )
    }

    #[wasm_bindgen(catch)]
    pub async fn sync_state(self) -> Result<()> {
        loop {
            let msgs = self.author.borrow_mut().fetch_next_msgs().await;
            if msgs.is_empty() {
                break;
            }
        }
        Ok(())
    }

    #[wasm_bindgen(catch)]
    pub async fn fetch_next_msgs(self) -> Result<Array> {
        let msgs = self.author.borrow_mut().fetch_next_msgs().await;
        let payloads = get_message_contents(msgs);
        Ok(payloads.into_iter().map(JsValue::from).collect())
    }

    #[wasm_bindgen(catch)]
    pub async fn fetch_prev_msg(self, link: Address) -> Result<UserResponse> {
        self.author
            .borrow_mut()
            .fetch_prev_msg(&link.try_into().map_or_else(|_err| ApiAddress::default(), |addr| addr))
            .await
            .map_or_else(
                |err| Err(JsValue::from_str(&err.to_string())),
                |msg| {
                    let msgs = vec![msg];
                    let responses = get_message_contents(msgs);
                    Ok(responses[0].copy())
                },
            )
    }

    #[wasm_bindgen(catch)]
    pub async fn fetch_prev_msgs(self, link: Address, num_msgs: usize) -> Result<Array> {
        self.author
            .borrow_mut()
            .fetch_prev_msgs(
                &link.try_into().map_or_else(|_err| ApiAddress::default(), |addr| addr),
                num_msgs,
            )
            .await
            .map_or_else(
                |err| Err(JsValue::from_str(&err.to_string())),
                |msgs| {
                    let responses = get_message_contents(msgs);
                    Ok(responses.into_iter().map(JsValue::from).collect())
                },
            )
    }

    #[wasm_bindgen(catch)]
    pub async fn gen_next_msg_ids(self) -> Result<Array> {
        let branching = self.author.borrow_mut().is_multi_branching();
        let mut ids = Vec::new();
        for (id, cursor) in self.author.borrow_mut().gen_next_msg_ids(branching).iter() {
            ids.push(NextMsgId::new(
                identifier_to_string(id),
                Address::from_string(cursor.link.to_string()),
            ));
        }
        Ok(ids.into_iter().map(JsValue::from).collect())
    }

    #[wasm_bindgen(catch)]
    pub fn fetch_state(&self) -> Result<Array> {
        self.author.borrow_mut().fetch_state().map_or_else(
            |err| Err(JsValue::from_str(&err.to_string())),
            |state_list| {
                Ok(state_list
                    .into_iter()
                    .map(|(id, cursor)| JsValue::from(UserState::new(id, cursor.into())))
                    .collect())
            },
        )
    }
}
