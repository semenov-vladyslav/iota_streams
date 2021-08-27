use iota_streams_app::transport::TransportOptions;

#[cfg(any(feature = "async-client", feature = "sync-client", feature = "wasm-client"))]
use iota_streams_app::transport::tangle::client::{
    Client,
    SendOptions,
};

#[cfg(not(any(feature = "async-client", feature = "sync-client", feature = "wasm-client")))]
use iota_streams_app::transport::{
    new_shared_transport,
    BucketTransport,
};

#[cfg(feature = "tangle")]
fn main() {
    use iota_streams_app_channels::api::tangle::test::example;

    #[cfg(any(feature = "async-client", feature = "sync-client", feature = "wasm-client"))]
    let tsp = {
        let mut tsp = Client::default();
        let mut send_opt = SendOptions::default();
        send_opt.url = "https://nodes.devnet.iota.org:443".to_string();
        tsp.set_send_options(send_opt);
        tsp
    };
    #[cfg(not(any(feature = "async-client", feature = "sync-client", feature = "wasm-client")))]
    let tsp = new_shared_transport(BucketTransport::new());

    #[cfg(not(feature = "async"))]
    assert!(dbg!(example(tsp)).is_ok());
    #[cfg(feature = "async")]
    assert!(dbg!(smol::block_on(example(tsp))).is_ok());
}

#[cfg(not(feature = "tangle"))]
fn main() {}
