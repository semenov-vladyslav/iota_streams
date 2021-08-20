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
        tangle::Author as ApiAuthor,
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
        ApiAuthor::import(&bytes, password, client.to_inner())
            .map(|v| Author {
                author: Rc::new(RefCell::new(v)),
            })
            .into_js_result()
    }

    #[wasm_bindgen(catch)]
    pub fn export(&self, password: &str) -> Result<Vec<u8>> {
        self.author.borrow_mut().export(password).into_js_result()
    }

    pub fn clone(&self) -> Author {
        Author {
            author: self.author.clone(),
        }
    }

    #[wasm_bindgen(catch)]
    pub fn channel_address(&self) -> Result<String> {
        self.author
            .borrow_mut()
            .channel_address()
            .map(|addr| addr.to_string())
            .ok_or("channel not created")
            .into_js_result()
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
        self.author.borrow_mut().store_psk(pskid, psk).into_js_result()?;
        Ok(pskid_str)
    }

    #[wasm_bindgen(catch)]
    pub fn get_public_key(&self) -> Result<String> {
        Ok(public_key_to_string(self.author.borrow_mut().get_public_key()))
    }

    #[wasm_bindgen(catch)]
    pub async fn send_announce(self) -> Result<UserResponse> {
        self.author
            .borrow_mut()
            .send_announce()
            .await
            .map(|addr| UserResponse::new(addr.into(), None, None))
            .into_js_result()
    }

    #[wasm_bindgen(catch)]
    pub async fn send_keyload_for_everyone(self, link: Address) -> Result<UserResponse> {
        self.author
            .borrow_mut()
            .send_keyload_for_everyone(link.as_inner())
            .await
            .map(|(link, seq_link)| UserResponse::new(link.into(), seq_link.map(Into::into), None))
            .into_js_result()
    }

    #[wasm_bindgen(catch)]
    pub async fn send_keyload(self, link: Address, psk_ids: PskIdsW, sig_pks: PublicKeysW) -> Result<UserResponse> {
        let pks = sig_pks.pks.into_iter().map(Into::<Identifier>::into);
        let psks = psk_ids.ids.into_iter().map(Into::<Identifier>::into);
        let identifiers: Vec<Identifier> = pks.chain(psks).collect();
        self.author
            .borrow_mut()
            .send_keyload(link.as_inner(), &identifiers)
            .await
            .map(|(link, seq_link)| UserResponse::new(link.into(), seq_link.map(Into::into), None))
            .into_js_result()
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
                link.as_inner(),
                &Bytes(public_payload.clone()),
                &Bytes(masked_payload.clone()),
            )
            .await
            .map(|(link, seq_link)| UserResponse::new(link.into(), seq_link.map(Into::into), None))
            .into_js_result()
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
            .send_signed_packet(link.as_inner(), &Bytes(public_payload), &Bytes(masked_payload))
            .await
            .map(|(link, seq_link)| UserResponse::new(link.into(), seq_link.map(Into::into), None))
            .into_js_result()
    }

    #[wasm_bindgen(catch)]
    pub async fn receive_subscribe(self, link_to: Address) -> Result<()> {
        self.author
            .borrow_mut()
            .receive_subscribe(link_to.as_inner())
            .await
            .into_js_result()
    }

    #[wasm_bindgen(catch)]
    pub async fn receive_tagged_packet(self, link: Address) -> Result<UserResponse> {
        self.author
            .borrow_mut()
            .receive_tagged_packet(link.as_inner())
            .await
            .map(|(pub_bytes, masked_bytes)| {
                UserResponse::new(link, None, Some(Message::new(None, pub_bytes.0, masked_bytes.0)))
            })
            .into_js_result()
    }

    #[wasm_bindgen(catch)]
    pub async fn receive_signed_packet(self, link: Address) -> Result<UserResponse> {
        self.author
            .borrow_mut()
            .receive_signed_packet(link.as_inner())
            .await
            .map(|(pk, pub_bytes, masked_bytes)| {
                UserResponse::new(
                    link,
                    None,
                    Some(Message::new(
                        Some(public_key_to_string(&pk)),
                        pub_bytes.0,
                        masked_bytes.0,
                    )),
                )
            })
            .into_js_result()
    }

    #[wasm_bindgen(catch)]
    pub async fn receive_sequence(self, link: Address) -> Result<Address> {
        self.author
            .borrow_mut()
            .receive_sequence(link.as_inner())
            .await
            .map(Into::into)
            .into_js_result()
    }

    #[wasm_bindgen(catch)]
    pub async fn receive_msg(self, link: Address) -> Result<UserResponse> {
        self.author
            .borrow_mut()
            .receive_msg(link.as_inner())
            .await
            .map(|msg| {
                let msgs = vec![msg];
                let responses = get_message_contents(msgs);
                responses[0].copy()
            })
            .into_js_result()
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
            .fetch_prev_msg(link.as_inner())
            .await
            .map(|msg| {
                let msgs = vec![msg];
                let responses = get_message_contents(msgs);
                responses[0].copy()
            })
            .into_js_result()
    }

    #[wasm_bindgen(catch)]
    pub async fn fetch_prev_msgs(self, link: Address, num_msgs: usize) -> Result<Array> {
        self.author
            .borrow_mut()
            .fetch_prev_msgs(link.as_inner(), num_msgs)
            .await
            .map(|msgs| {
                let responses = get_message_contents(msgs);
                responses.into_iter().map(JsValue::from).collect()
            })
            .into_js_result()
    }

    #[wasm_bindgen(catch)]
    pub async fn gen_next_msg_ids(self) -> Result<Array> {
        let branching = self.author.borrow_mut().is_multi_branching();
        let mut ids = Vec::new();
        for (id, cursor) in self.author.borrow_mut().gen_next_msg_ids(branching).iter() {
            ids.push(NextMsgId::new(identifier_to_string(id), cursor.link.into()));
        }
        Ok(ids.into_iter().map(JsValue::from).collect())
    }

    #[wasm_bindgen(catch)]
    pub fn fetch_state(&self) -> Result<Array> {
        self.author
            .borrow_mut()
            .fetch_state()
            .map(|state_list| {
                state_list
                    .into_iter()
                    .map(|(id, cursor)| JsValue::from(UserState::new(id, cursor.into())))
                    .collect()
            })
            .into_js_result()
    }
}
