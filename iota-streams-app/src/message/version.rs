//! Streams message syntax version distinguished between incompatible changes in DDML
//! syntax and/or rules of processing DDML messages. It usually means that a new
//! command or type is added, or command proceeds in a different manner than before.
//! It can also signify changes in the `Header` message.
//!
//! Note, changes in syntax of Messages of a particular Application should be reflected
//! in `Header.content_type` field or the Content Message should implicitly support
//! versioning (ie. include `content_version` field for example).
//!
//! Streams message syntax version is indicated as the first byte in the binary encoded message.
//!
//! Backwards compatibility of the Streams implementations is welcome and not mandatory.

use iota_streams_ddml::types::Uint8;

/// Streams version number.
pub const STREAMS_1_VER: Uint8 = Uint8(0);

/// Encoding Constants
pub const UTF8: Uint8 = Uint8(0);

//
pub const HDF_ID: Uint8 = Uint8(4);
pub const INIT_PCF_ID: Uint8 = Uint8(5);
pub const INTER_PCF_ID: Uint8 = Uint8(12);
pub const FINAL_PCF_ID: Uint8 = Uint8(14);
