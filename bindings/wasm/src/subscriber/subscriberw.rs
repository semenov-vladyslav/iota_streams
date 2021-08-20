use js_sys::Array;
use wasm_bindgen::prelude::*;

use crate::{
    types::*,
    user::userw::*,
};

use core::cell::RefCell;
use iota_streams::{
    app::transport::{
        tangle::client::Client as ApiClient,
        TransportOptions,
    },
    app_channels::api::{
        psk_from_seed,
        pskid_from_psk,
        tangle::Subscriber as ApiSubscriber,
    },
    core::{
        prelude::{
            Rc,
            String,
        },
        psk::pskid_to_hex_string,
    },
    ddml::types::*,
};

#[wasm_bindgen]
pub struct Subscriber {
    subscriber: Rc<RefCell<ApiSubscriber<ClientWrap>>>,
}

#[wasm_bindgen]
impl Subscriber {
    #[wasm_bindgen(constructor)]
    pub fn new(seed: String, options: SendOptions) -> Subscriber {
        let mut client = ApiClient::new_from_url(&options.url());
        client.set_send_options(options.into());
        let transport = Rc::new(RefCell::new(client));

        let subscriber = Rc::new(RefCell::new(ApiSubscriber::new(&seed, transport)));
        Subscriber { subscriber }
    }

    pub fn from_client(client: Client, seed: String) -> Subscriber {
        let subscriber = Rc::new(RefCell::new(ApiSubscriber::new(&seed, client.to_inner())));
        Subscriber { subscriber }
    }

    #[wasm_bindgen(catch)]
    pub fn import(client: Client, bytes: Vec<u8>, password: &str) -> Result<Subscriber> {
        ApiSubscriber::import(&bytes, password, client.to_inner())
            .map(|v| Subscriber {
                subscriber: Rc::new(RefCell::new(v)),
            })
            .into_js_result()
    }

    pub fn clone(&self) -> Subscriber {
        Subscriber {
            subscriber: self.subscriber.clone(),
        }
    }

    #[wasm_bindgen(catch)]
    pub fn channel_address(&self) -> Result<String> {
        self.subscriber
            .borrow_mut()
            .channel_address()
            .map(|addr| addr.to_string())
            .ok_or("channel not subscribed")
            .into_js_result()
    }

    #[wasm_bindgen(catch)]
    pub fn get_client(&self) -> Client {
        Client(self.subscriber.borrow_mut().get_transport().clone())
    }

    #[wasm_bindgen(catch)]
    pub fn is_multi_branching(&self) -> Result<bool> {
        Ok(self.subscriber.borrow_mut().is_multi_branching())
    }

    #[wasm_bindgen(catch)]
    pub fn store_psk(&self, psk_seed_str: String) -> Result<String> {
        let psk = psk_from_seed(psk_seed_str.as_bytes());
        let pskid = pskid_from_psk(&psk);
        let pskid_str = pskid_to_hex_string(&pskid);
        self.subscriber.borrow_mut().store_psk(pskid, psk).into_js_result()?;
        Ok(pskid_str)
    }

    #[wasm_bindgen(catch)]
    pub fn get_public_key(&self) -> Result<String> {
        Ok(public_key_to_string(self.subscriber.borrow_mut().get_public_key()))
    }

    #[wasm_bindgen(catch)]
    pub fn author_public_key(&self) -> Result<String> {
        self.subscriber
            .borrow_mut()
            .author_public_key()
            .ok_or("channel not registered, author's public key not found")
            .map(|author_pk| hex::encode(author_pk.to_bytes()))
            .into_js_result()
    }

    #[wasm_bindgen(catch)]
    pub fn is_registered(&self) -> Result<bool> {
        Ok(self.subscriber.borrow_mut().is_registered())
    }

    #[wasm_bindgen(catch)]
    pub fn unregister(&self) -> Result<()> {
        self.subscriber.borrow_mut().unregister();
        Ok(())
    }

    #[wasm_bindgen(catch)]
    pub fn export(&self, password: &str) -> Result<Vec<u8>> {
        self.subscriber.borrow_mut().export(password).into_js_result()
    }

    #[wasm_bindgen(catch)]
    pub async fn receive_announcement(self, link: Address) -> Result<()> {
        self.subscriber
            .borrow_mut()
            .receive_announcement(link.as_inner())
            .await
            .into_js_result()
    }

    #[wasm_bindgen(catch)]
    pub async fn receive_keyload(self, link: Address) -> Result<bool> {
        self.subscriber
            .borrow_mut()
            .receive_keyload(link.as_inner())
            .await
            .into_js_result()
    }

    #[wasm_bindgen(catch)]
    pub async fn receive_tagged_packet(self, link: Address) -> Result<UserResponse> {
        self.subscriber
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
        self.subscriber
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
        self.subscriber
            .borrow_mut()
            .receive_sequence(link.as_inner())
            .await
            .map(Into::into)
            .into_js_result()
    }

    #[wasm_bindgen(catch)]
    pub async fn receive_msg(self, link: Address) -> Result<UserResponse> {
        self.subscriber
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
    pub async fn send_subscribe(self, link: Address) -> Result<UserResponse> {
        self.subscriber
            .borrow_mut()
            .send_subscribe(link.as_inner())
            .await
            .map(|link| UserResponse::new(link.into(), None, None))
            .into_js_result()
    }

    #[wasm_bindgen(catch)]
    pub async fn send_tagged_packet(
        self,
        link: Address,
        public_payload: Vec<u8>,
        masked_payload: Vec<u8>,
    ) -> Result<UserResponse> {
        self.subscriber
            .borrow_mut()
            .send_tagged_packet(link.as_inner(), &Bytes(public_payload), &Bytes(masked_payload))
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
        self.subscriber
            .borrow_mut()
            .send_signed_packet(link.as_inner(), &Bytes(public_payload), &Bytes(masked_payload))
            .await
            .map(|(link, seq_link)| UserResponse::new(link.into(), seq_link.map(Into::into), None))
            .into_js_result()
    }

    #[wasm_bindgen(catch)]
    pub async fn sync_state(self) -> Result<()> {
        loop {
            let msgs = self.subscriber.borrow_mut().fetch_next_msgs().await;
            if msgs.is_empty() {
                break;
            }
        }
        Ok(())
    }

    #[wasm_bindgen(catch)]
    pub async fn fetch_next_msgs(self) -> Result<Array> {
        let msgs = self.subscriber.borrow_mut().fetch_next_msgs().await;
        let payloads = get_message_contents(msgs);
        Ok(payloads.into_iter().map(JsValue::from).collect())
    }

    #[wasm_bindgen(catch)]
    pub async fn fetch_prev_msg(self, link: Address) -> Result<UserResponse> {
        self.subscriber
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
        self.subscriber
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
    pub fn fetch_state(&self) -> Result<Array> {
        self.subscriber
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

    #[wasm_bindgen(catch)]
    pub fn reset_state(self) -> Result<()> {
        self.subscriber.borrow_mut().reset_state().into_js_result()
    }
}
