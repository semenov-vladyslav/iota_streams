#![allow(non_snake_case)]
#![allow(dead_code)]
//#![no_std]

use std::env;

use rand::Rng;

use iota_streams::{
    app::transport::tangle::client::Client,
    app_channels::api::tangle::{
        ChannelType,
        Transport,
    },
    core::{
        prelude::{
            Rc,
            String,
        },
        Result,
    },
};

use core::cell::RefCell;

mod branching;

fn run_recovery_test<T: Transport>(transport: Rc<RefCell<T>>, seed: &str) {
    println!("\tRunning Recovery Test, seed: {}", seed);
    match branching::recovery::example(transport, ChannelType::SingleBranch, seed) {
        Err(err) => println!("Error in recovery test: {:?}", err),
        Ok(_) => println!("\tRecovery test completed!!"),
    }
    println!("#######################################");
}

fn run_single_branch_test<T: Transport>(transport: Rc<RefCell<T>>, seed: &str) {
    println!("\tRunning Single Branch Test, seed: {}", seed);
    match branching::single_branch::example(transport, ChannelType::SingleBranch, seed) {
        Err(err) => println!("Error in Single Branch test: {:?}", err),
        Ok(_) => println!("\tSingle Branch Test completed!!"),
    }
    println!("#######################################");
}

fn run_single_depth_test<T: Transport>(transport: Rc<RefCell<T>>, seed: &str) {
    println!("\tRunning Single Branch Test, seed: {}", seed);
    match branching::single_depth::example(transport, ChannelType::SingleDepth, seed) {
        Err(err) => println!("Error in Single Depth test: {:?}", err),
        Ok(_) => println!("\tSingle Depth Test completed!!"),
    }
    println!("#######################################");
}

fn run_multi_branch_test<T: Transport>(transport: Rc<RefCell<T>>, seed: &str) {
    println!("\tRunning Multi Branch Test, seed: {}", seed);
    match branching::multi_branch::example(transport, ChannelType::MultiBranch, seed) {
        Err(err) => println!("Error in Multi Branch test: {:?}", err),
        Ok(_) => println!("\tMulti Branch Test completed!!"),
    }
    println!("#######################################");
}

fn run_main<T: Transport>(transport: T) -> Result<()> {
    let seed1: &str = "SEEDSINGLE";
    let seed2: &str = "SEEDMULTI9";
    let seed3: &str = "SEEDRECOVERY";

    let transport = Rc::new(RefCell::new(transport));
    run_single_branch_test(transport.clone(), seed1);
    run_multi_branch_test(transport.clone(), seed2);
    run_recovery_test(transport, seed3);

    Ok(())
}

#[allow(dead_code)]
fn main_pure() {
    let transport = iota_streams::app_channels::api::tangle::BucketTransport::new();

    println!("#######################################");
    println!("Running pure tests without accessing Tangle");
    println!("#######################################");
    println!("\n");

    let transport = Rc::new(RefCell::new(transport));
    run_single_branch_test(transport.clone(), "PURESEEDA");
    run_single_depth_test(transport.clone(), "PURESEEDB");
    run_multi_branch_test(transport.clone(), "PURESEEDC");
    run_recovery_test(transport, "PURESEEDD");
    println!("Done running pure tests without accessing Tangle");
    println!("#######################################");
}

#[allow(dead_code)]
fn main_client() {
    // Load or .env file, log message if we failed
    if dotenv::dotenv().is_err() {
        println!(".env file not found; copy and rename example.env to \".env\"");
    };

    // Parse env vars with a fallback
    let node_url = env::var("URL").unwrap_or_else(|_| "https://chrysalis-nodes.iota.org".to_string());

    let client = Client::new_from_url(&node_url);

    let transport = Rc::new(RefCell::new(client));

    println!("#######################################");
    println!("Running tests accessing Tangle via node {}", &node_url);
    println!("#######################################");
    println!("\n");

    run_single_branch_test(transport.clone(), &new_seed());
    run_single_depth_test(transport.clone(), &new_seed());
    run_multi_branch_test(transport.clone(), &new_seed());
    run_recovery_test(transport, &new_seed());
    println!("Done running tests accessing Tangle via node {}", &node_url);
    println!("#######################################");
}

fn new_seed() -> String {
    let alph9 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ9";
    (0..10).map(|_| alph9.chars().nth(rand::thread_rng().gen_range(0, 27)).unwrap())
        .collect::<String>()
}

#[tokio::main]
async fn main() {
    main_pure();
    // main_client();
}
