# Getting Started
The WASM bindings allow for you to build a Streams API for web applications and nodejs. 
The streams instance underlying the bindings is built with the `wasm-client` flag to 
ensure a compatible client interface using the `iota.rs iota-client` crate. 

Before building anything you'll need to make sure you have `npm` installed on your 
machine.

To build the library, first make sure you're in the wasm directory:
```cd bindings/wasm``` and run ```npm install``` to sync up your dependencies. 

For building the nodejs compatible api, run:
```bash
npm run build:nodejs  <- Builds to node/iota_streams_wasm
```

And for building the web compatible api, run:
```bash 
npm run build:web  <- Builds to web/iota_streams_wasm
```


### Starting a Channel 
Once the package has been built, you can pull it into a script file like so: 
```javascript
const streams = require("./node/iota_streams_wasm");

let node = "https://chrysalis-nodes.iota.org/";
// Options include: (node-url, depth, local pow, # of threads)
let options = new streams.SendOptions(node, 3, true, 1);

// Author generated with: (Seed, Options, Multi-branching flag)
let auth = new streams.Author("Unique Seed Here", options, false);

// Response formatting: { link, sequence link, msg }
let response = await auth.clone().send_announce();
let ann_link = response.get_link();
console.log("Channel Announcement at: ", ann_link.to_string());
```
