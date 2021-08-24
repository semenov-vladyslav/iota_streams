use iota_streams::{
    app_channels::api::tangle::{
        Author,
        ChannelType,
        Subscriber,
        Transport,
    },
    core::{
        panic_if_not,
        prelude::Rc,
        println,
        Result,
    },
    ddml::types::*,
};

use core::cell::RefCell;

use super::utils;
use std::{
    thread::sleep,
    time::Duration,
};

pub fn example<T: Transport>(transport: Rc<RefCell<T>>, channel_type: ChannelType, seed: &str) -> Result<()> {
    let mut author = Author::new(seed, channel_type.clone(), transport.clone());
    println!("Author multi branching?: {}", author.is_multi_branching());

    let mut subscriberA = Subscriber::new("SUBSCRIBERA9SEED", transport.clone());

    let public_payload = Bytes("PUBLICPAYLOAD".as_bytes().to_vec());
    let masked_payload = Bytes("MASKEDPAYLOAD".as_bytes().to_vec());

    println!("\nAnnounce Channel");
    let announcement_link = {
        let msg = author.send_announce()?;
        println!("  msg => <{}> <{:x}>", msg.msgid, msg.to_msg_index());
        msg
    };
    println!("  Author channel address: {}", author.channel_address().unwrap());

    println!("\nHandle Announce Channel");
    subscriberA.receive_announcement(&announcement_link)?;

    println!("\nSubscribe A");
    let subscribeA_link = {
        let msg = subscriberA.send_subscribe(&announcement_link)?;
        println!("  msg => <{}> <{:x}>", msg.msgid, msg.to_msg_index());
        msg
    };

    println!("\nHandle Subscribe A");
    author.receive_subscribe(&subscribeA_link)?;

    println!("\nShare keyload");
    let mut previous_msg_link = {
        let (msg, seq) = author.send_keyload_for_everyone(&announcement_link)?;
        println!("  msg => <{}> <{:x}>", msg.msgid, msg.to_msg_index());
        panic_if_not(seq.is_none());
        msg
    };

    for i in 1..6 {
        println!("Signed packet {} - Author", i);
        previous_msg_link = {
            let (msg, seq) = author.send_signed_packet(&previous_msg_link, &public_payload, &masked_payload)?;
            println!("  msg => <{}> <{:x}>", msg.msgid, msg.to_msg_index());
            panic_if_not(seq.is_none());
            msg
        };
    }

    println!("\nWait a moment for messages to propogate...");
    sleep(Duration::from_secs(3));
    println!("Subscriber A fetching transactions...");
    utils::s_fetch_next_messages(&mut subscriberA);

    for i in 6..11 {
        println!("Tagged packet {} - SubscriberA", i);
        previous_msg_link = {
            let (msg, seq) = subscriberA.send_tagged_packet(&previous_msg_link, &public_payload, &masked_payload)?;
            println!("  msg => <{}> <{:x}>", msg.msgid, msg.to_msg_index());
            panic_if_not(seq.is_none());
            msg
        };
    }

    println!("\nWait a moment for messages to propogate...");
    sleep(Duration::from_secs(3));
    println!("Author fetching transactions...");
    utils::a_fetch_next_messages(&mut author);

    println!("\n\nTime to try to recover the instance...");
    let mut new_author = Author::recover(seed, &announcement_link, channel_type, transport)?;

    let state = new_author.fetch_state()?;
    let old_state = author.fetch_state()?;

    let mut latest_link = &announcement_link;

    for (pk, cursor) in state.iter() {
        let mut exists = false;
        for (p, c) in old_state.iter() {
            if pk == p && cursor.link == c.link && cursor.branch_no == c.branch_no && cursor.seq_no == c.seq_no {
                // Set latest link for sequencing later
                latest_link = &cursor.link;
                exists = true
            }
        }
        panic_if_not!(exists);
    }

    println!("States match...\nSending next sequenced message...");
    let (last_msg, _seq) = new_author.send_signed_packet(latest_link, &public_payload, &masked_payload)?;
    println!("  msg => <{}> <{:x}>", last_msg.msgid, last_msg.to_msg_index());

    // Wait a second for message to propagate
    sleep(Duration::from_secs(1));
    println!("\nSubscriber A fetching transactions...");
    let msgs = subscriberA.fetch_next_msgs();
    panic_if_not!(!msgs.is_empty());

    let mut matches = false;
    for msg in msgs {
        if last_msg == msg.link {
            matches = true
        }
    }
    panic_if_not!(matches);

    println!("Last message matches, recovery, sync and send successful");
    Ok(())
}
