use core::convert::TryInto as _;
use wasm_bindgen::prelude::*;

use crate::types::*;

use iota_streams::{
    app::transport::{
        tangle::client::Client as ApiClient,
        TransportDetails,
        TransportOptions,
    },
    app_channels::api::tangle::Address as ApiAddress,
    core::{
        futures::executor::block_on,
        prelude::{
            Arc,
            Mutex,
        },
    },
};

#[wasm_bindgen]
#[derive(Clone)]
pub struct Client(pub(crate) ClientWrap);

#[wasm_bindgen]
impl Client {
    #[wasm_bindgen(constructor)]
    pub fn new(node: String, options: SendOptions) -> Self {
        let mut client = ApiClient::new_from_url(&node);
        block_on(client.set_send_options(options.into()));
        let transport = Arc::new(Mutex::new(client));

        Client(transport)
    }

    #[wasm_bindgen(catch)]
    pub async fn get_link_details(mut self, link: Address) -> Result<Details> {
        self.0
            .get_link_details(
                &link
                    .try_into()
                    .map_or_else(|_err| ApiAddress::default(), |addr: ApiAddress| addr),
            )
            .await
            .map_or_else(
                |err| Err(JsValue::from_str(&err.to_string())),
                |details| Ok(details.into()),
            )
    }
}

impl Client {
    #[allow(clippy::wrong_self_convention)]
    pub fn to_inner(self) -> ClientWrap {
        self.0
    }
}

impl From<ApiClient> for Client {
    fn from(client: ApiClient) -> Self {
        let transport = Arc::new(Mutex::new(client));

        Client(transport)
    }
}
