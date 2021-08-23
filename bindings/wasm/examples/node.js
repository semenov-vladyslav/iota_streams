const streams = require("../node/iota_streams_wasm");
const fetch = require("node-fetch");

global.fetch = fetch;
global.Headers = fetch.Headers;
global.Request = fetch.Request;
global.Response = fetch.Response;

streams.set_panic_hook();

main()
  .then(() => {
    console.log("Done example");
  })
  .catch((err) => {
    console.log(err);
  });

async function main() {
  // Default is a load balancer, if you have your own node it's recommended to use that instead
  let node = "https://chrysalis-nodes.iota.org/";
  let options = new streams.SendOptions(node, true);
  let seed = make_seed(81);
  let auth = new streams.Author(seed, options.clone(), streams.ChannelType.SingleBranch);

  console.log("channel address: ", auth.channel_address());
  console.log("multi branching: ", auth.is_multi_branching());

  let response = await auth.clone().send_announce();
  let ann_link = response.link;
  console.log("announced at: ", ann_link.toString());
  console.log("Announce message index: " + ann_link.toMsgIndexHex());

  let details = await auth.clone().get_client().get_link_details(ann_link);
  console.log("Announce message id: " + details.get_metadata().message_id);

  let seed2 = make_seed(81);
  let sub = new streams.Subscriber(seed2, options.clone());
  await sub.clone().receive_announcement(ann_link.copy());
  let author_pk = sub.author_public_key();
  console.log("Channel registered by subscriber, author's public key: ", author_pk);

  // copy state for comparison after reset later
  let start_state = sub.fetch_state();

  console.log("Subscribing...");
  response = await sub.clone().send_subscribe(ann_link.copy());
  let sub_link = response.link;
  console.log("Subscription message at: ", sub_link.toString());
  console.log("Subscription message index: " + sub_link.toMsgIndexHex());
  await auth.clone().receive_subscribe(sub_link);
  console.log("Subscription processed");

  console.log("Sending Keyload");
  response = await auth.clone().send_keyload_for_everyone(ann_link.copy());
  let keyload_link = response.link;
  console.log("Keyload message at: ", keyload_link.toString());
  console.log("Keyload message index: " + keyload_link.toMsgIndexHex());

  console.log("Subscriber syncing...");
  await sub.clone().sync_state();

  let public_payload = to_bytes("Public");
  let masked_payload = to_bytes("Masked");

  console.log("Subscriber Sending tagged packet");
  response = await sub
    .clone()
    .send_tagged_packet(keyload_link, public_payload, masked_payload);
  let tag_link = response.link;
  console.log("Tag packet at: ", tag_link.toString());
  console.log("Tag packet index: " + tag_link.toMsgIndexHex());

  let last_link = tag_link;
  console.log("Subscriber Sending multiple signed packets");

  for (var x = 0; x < 10; x++) {
    response = await sub
      .clone()
      .send_signed_packet(last_link, public_payload, masked_payload);
    last_link = response.link;
    console.log("Signed packet at: ", last_link.toString());
    console.log("Signed packet index: " + last_link.toMsgIndexHex());
  }

  console.log("\nAuthor fetching next messages");
  let exists = true;
  while (exists) {
    let next_msgs = await auth.clone().fetch_next_msgs();

    if (next_msgs.length === 0) {
      exists = false;
    }

    for (var i = 0; i < next_msgs.length; i++) {
      console.log("Found a message...");
      console.log(
        "Public: ",
        from_bytes(next_msgs[i].message.get_public_payload()),
        "\tMasked: ",
        from_bytes(next_msgs[i].message.get_masked_payload())
      );
    }
  }

  console.log("\nSubscriber resetting state");
  sub.clone().reset_state();
  let reset_state = sub.fetch_state();

  var matches = true;
  for (var i = 0; i < reset_state.length; i++) {
    if (start_state[i].link.toString() != reset_state[i].link.toString() ||
        start_state[i].seqNo != reset_state[i].seqNo ||
        start_state[i].branchNo != reset_state[i].branchNo) {
      matches = false;
    }
  }

  if (matches) { console.log("States match"); } else { console.log("States do not match"); }

  console.log("\nAuthor fetching prev messages");
  let prev_msgs = await auth.clone().fetch_prev_msgs(last_link, 3);
  for (var j = 0; j < prev_msgs.length; j++) {
    console.log("Found a message at ", prev_msgs[j].link.toString());
    console.log("Found a message at index: " + prev_msgs[j].link.toMsgIndexHex());
  }

  // Import export example
  // TODO: Use stronghold
  let password = "password"
  let exp = auth.clone().export(password);

  let client = new streams.Client(node, options.clone());
  let auth2 = streams.Author.import(client, exp, password);

  if (auth2.channel_address !== auth.channel_address) {
      console.log("import failed");
  } else {
      console.log("import succesfull")
  }

  function to_bytes(str) {
    var bytes = [];
    for (var i = 0; i < str.length; ++i) {
      bytes.push(str.charCodeAt(i));
    }
    return bytes;
  }

  function from_bytes(bytes) {
    var str = "";
    for (var i = 0; i < bytes.length; ++i) {
      str += String.fromCharCode(bytes[i]);
    }
    return str;
  }

  function make_seed(size) {
    const alphabet = "abcdefghijklmnopqrstuvwxyz";
    let seed = "";
    for (i = 9; i < size; i++) {
      seed += alphabet[Math.floor(Math.random() * alphabet.length)];
    }
    return seed;
  }
}
