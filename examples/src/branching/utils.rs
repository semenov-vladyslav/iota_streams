use iota_streams::{
    app::message::HasLink,
    app_channels::api::tangle::{
        Author,
        Subscriber,
        Transport,
    },
};

pub fn s_fetch_next_messages<T: Transport + Clone>(subscriber: &mut Subscriber<T>) {
    let mut exists = true;

    while exists {
        let msgs = subscriber.fetch_next_msgs();
        exists = false;

        for msg in msgs {
            println!("Message exists at {}... ", &msg.link.rel());
            exists = true;
        }

        if !exists {
            println!("No more messages in sequence.");
        }
    }
}

pub fn a_fetch_next_messages<T: Transport + Clone>(author: &mut Author<T>) {
    let mut exists = true;

    while exists {
        let msgs = author.fetch_next_msgs();
        exists = false;

        for msg in msgs {
            println!("Message exists at {}... ", &msg.link.rel());
            exists = true;
        }

        if !exists {
            println!("No more messages in sequence.");
        }
    }
}
