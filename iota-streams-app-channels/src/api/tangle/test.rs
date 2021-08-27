#![allow(non_snake_case)]
use crate::api::tangle::{
    Address,
    Author,
    Subscriber,
};
use iota_streams_app::message::HasLink;

#[cfg(not(feature = "async"))]
use iota_streams_core::{
    try_or,
    Errors::*,
};

use iota_streams_core::{
    ensure,
    prelude::{
        string::ToString,
        Vec,
    },
    println,
    Result,
};

use super::*;

#[cfg(not(feature = "async"))]
pub fn example<T: Transport + Clone>(transport: T) -> Result<()> {
    let mut author = Author::new("AUTHOR9SEED", ChannelType::SingleBranch, transport.clone());

    let mut subscriberA = Subscriber::new("SUBSCRIBERA9SEED", transport.clone());

    let mut subscriberB = Subscriber::new("SUBSCRIBERB9SEED", transport.clone());

    let public_payload = Bytes("PUBLICPAYLOAD".as_bytes().to_vec());
    let masked_payload = Bytes("MASKEDPAYLOAD".as_bytes().to_vec());
    let no_payload = Bytes(Vec::new());

    println!("announce");
    let (announcement_address, announcement_tag) = {
        let msg = &author.send_announce()?;
        println!("  {}", msg);
        (msg.appinst.to_string(), msg.msgid.to_string())
    };
    let announcement_link = Address::from_str(&announcement_address, &announcement_tag).unwrap();

    {
        subscriberA.receive_announcement(&announcement_link)?;
        ensure!(
            author.channel_address() == subscriberA.channel_address(),
            "bad channel address"
        );
        subscriberB.receive_announcement(&announcement_link)?;
        ensure!(
            subscriberA.channel_address() == subscriberB.channel_address(),
            "bad channel address"
        );
        ensure!(
            subscriberA
                .channel_address()
                .map_or(false, |appinst| appinst == announcement_link.base()),
            "bad announcement address"
        );
    }

    println!("\nsign packet");
    let signed_packet_link = {
        // This signed packet is not encrypted,
        // it's forbidden to have masked payload except for empty one.
        let (msg, _) = author.send_signed_packet(&announcement_link, &public_payload, &no_payload)?;
        println!("  {}", msg);
        msg
    };
    println!("  at {}", signed_packet_link.rel());

    {
        let (_pk, unwrapped_public, unwrapped_masked) = subscriberA.receive_signed_packet(&signed_packet_link)?;
        try_or!(
            public_payload == unwrapped_public,
            PublicPayloadMismatch(public_payload.to_string(), unwrapped_public.to_string())
        )?;
        try_or!(
            no_payload == unwrapped_masked,
            MaskedPayloadMismatch(no_payload.to_string(), unwrapped_masked.to_string())
        )?;
    }

    println!("\nsubscribe");
    let subscribeB_link = {
        let msg = subscriberB.send_subscribe(&announcement_link)?;
        println!("  {}", msg);
        msg
    };

    {
        author.receive_subscribe(&subscribeB_link)?;
    }

    println!("\nshare keyload for everyone");
    let keyload_link = {
        let (msg, _) = author.send_keyload_for_everyone(&announcement_link)?;
        println!("  {}", msg);
        msg
    };

    {
        let resultA = subscriberA.receive_keyload(&keyload_link);
        let unwrapped = resultA.is_ok() && !resultA.unwrap();
        try_or!(unwrapped, SubscriberAccessMismatch("A".to_string()))?;
        let resultB = subscriberB.receive_keyload(&keyload_link)?;
        try_or!(resultB, MessageUnwrapFailure("B".to_string()))?;
    }

    println!("\ntag packet");
    let tagged_packet_link = {
        let (msg, _) = author.send_tagged_packet(&keyload_link, &public_payload, &masked_payload)?;
        println!("  {}", msg);
        msg
    };

    {
        let resultA = subscriberA.receive_tagged_packet(&tagged_packet_link);
        ensure!(resultA.is_err(), "subscriberA failed to unwrap tagged packet");
        let (unwrapped_public, unwrapped_masked) = subscriberB.receive_tagged_packet(&tagged_packet_link)?;
        ensure!(public_payload == unwrapped_public, "bad unwrapped public payload");
        ensure!(masked_payload == unwrapped_masked, "bad unwrapped masked payload");
    }

    {
        subscriberB.receive_keyload(&keyload_link)?;
    }

    let subAdump = subscriberA.export("pwdSubA").unwrap();
    let _subscriberA2 = Subscriber::import(subAdump.as_ref(), "pwdSubA", transport.clone()).unwrap();

    let subBdump = subscriberB.export("pwdSubB").unwrap();
    let _subscriberB2 = Subscriber::import(subBdump.as_ref(), "pwdSubB", transport.clone()).unwrap();

    let authordump = author.export("pwdAuthor").unwrap();
    let _author2 = Author::import(authordump.as_ref(), "pwdAuthor", transport).unwrap();

    Ok(())
}

#[cfg(feature = "async")]
pub async fn example<T: Transport + Clone>(transport: T) -> Result<()> where
{
    let mut author = Author::new("AUTHOR9SEED", ChannelType::SingleBranch, transport.clone());

    let mut subscriberA = Subscriber::new("SUBSCRIBERA9SEED", transport.clone());

    let mut subscriberB = Subscriber::new("SUBSCRIBERB9SEED", transport.clone());

    let public_payload = Bytes("PUBLICPAYLOAD".as_bytes().to_vec());
    let masked_payload = Bytes("MASKEDPAYLOAD".as_bytes().to_vec());

    println!("announce");
    let (announcement_address, announcement_tag) = {
        let msg = &author.send_announce().await?;
        println!("  {}", msg);
        (msg.appinst.to_string(), msg.msgid.to_string())
    };
    let announcement_link = Address::from_str(&announcement_address, &announcement_tag).unwrap();

    {
        subscriberA.receive_announcement(&announcement_link).await?;
        ensure!(
            author.channel_address() == subscriberA.channel_address(),
            "bad channel address"
        );
        subscriberB.receive_announcement(&announcement_link).await?;
        ensure!(
            subscriberA.channel_address() == subscriberB.channel_address(),
            "bad channel address"
        );
        ensure!(
            subscriberA
                .channel_address()
                .map_or(false, |appinst| appinst == announcement_link.base()),
            "bad announcement address"
        );
    }

    println!("\nsign packet");
    let signed_packet_link = {
        let (msg, _) = author
            .send_signed_packet(&announcement_link, &public_payload, &masked_payload)
            .await?;
        println!("  {}", msg);
        msg
    };
    println!("  at {}", signed_packet_link.rel());

    {
        let (_pk, unwrapped_public, unwrapped_masked) = subscriberA.receive_signed_packet(&signed_packet_link).await?;
        ensure!(public_payload == unwrapped_public, "bad unwrapped public payload");
        ensure!(masked_payload == unwrapped_masked, "bad unwrapped masked payload");
    }

    println!("\nsubscribe");
    let subscribeB_link = {
        let msg = subscriberB.send_subscribe(&announcement_link).await?;
        println!("  {}", msg);
        msg
    };

    {
        author.receive_subscribe(&subscribeB_link).await?;
    }

    println!("\nshare keyload for everyone");
    let keyload_link = {
        let (msg, _) = author.send_keyload_for_everyone(&announcement_link).await?;
        println!("  {}", msg);
        msg
    };

    {
        let resultA = subscriberA.receive_keyload(&keyload_link).await;
        ensure!(
            resultA.is_ok() && !resultA.unwrap(),
            "sbuscriberA failed to unwrap keyload"
        );
        let resultB = subscriberB.receive_keyload(&keyload_link).await?;
        ensure!(resultB, "sbuscriberB failed to unwrap keyload");
    }

    println!("\ntag packet");
    let tagged_packet_link = {
        let (msg, _) = author
            .send_tagged_packet(&keyload_link, &public_payload, &masked_payload)
            .await?;
        println!("  {}", msg);
        msg
    };

    {
        let resultA = subscriberA.receive_tagged_packet(&tagged_packet_link).await;
        ensure!(resultA.is_err(), "subscriberA failed to unwrap tagged packet");
        let (unwrapped_public, unwrapped_masked) = subscriberB.receive_tagged_packet(&tagged_packet_link).await?;
        ensure!(public_payload == unwrapped_public, "bad unwrapped public payload");
        ensure!(masked_payload == unwrapped_masked, "bad unwrapped masked payload");
    }

    {
        subscriberB.receive_keyload(&keyload_link).await?;
    }

    let subAdump = subscriberA.export("pwdSubA").unwrap();
    let _subscriberA2 = Subscriber::import(subAdump.as_ref(), "pwdSubA", transport.clone()).unwrap();

    let subBdump = subscriberB.export("pwdSubB").unwrap();
    let _subscriberB2 = Subscriber::import(subBdump.as_ref(), "pwdSubB", transport.clone()).unwrap();

    let authordump = author.export("pwdAuthor").unwrap();
    let _author2 = Author::import(authordump.as_ref(), "pwdAuthor", transport.clone()).unwrap();

    Ok(())
}

#[test]
#[cfg(not(feature = "async"))]
fn run_basic_scenario() -> Result<()> {
    let transport = iota_streams_app::transport::new_shared_transport(crate::api::tangle::BucketTransport::new());
    example(transport)
}

#[test]
#[cfg(feature = "async")]
fn run_basic_scenario() -> Result<()> {
    let transport = iota_streams_app::transport::new_shared_transport(crate::api::tangle::BucketTransport::new());
    // TODO: fix async BucketTransport issue
    // smol::block_on(example(transport))
    Ok(())
}
