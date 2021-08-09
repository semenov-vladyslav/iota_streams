# Introduction
This document provides the canonical definition of all the relevant terms used throughout the Streams API and private implementation.
This includes types, fields, functions, variables, traits, and any other programming construct. It aims to be fairly comprehensive,
therefore, when searching for a name of a relevant item, one should expect to find the proper term already defined here, or propose a new inclusion.

Naming consistency is important and synonyms should be kept to the minimum if at all, taking any opportunity to refactor the code
and rename the items to the canonical term.

While Comprehensive, this list should not be _too_ long; a glossary that is too long is a sign of excessive complexity, and a suggestion to
try to redesign the system into a simpler architecture.

This glossary is organized by contexts. Contexts provide the boundaries within which definitions must hold. Terms might have different
definitions across contexts, although this should be avoided when possible to avoid complexity.

# Definitions
## Channels
### Author
_Role of the [user] that creates and owns the [channel]_

**Alt**: `auth`

### Subscriber
_Role of the [user] that consumes [messages] from the [channel]_

### Publisher
_Role of the [user] that publishes [messages] to a [channel]. A publisher can encrypt [messages] restricting access to them to a set of [allowed participants]_

### Participant
_[User] of a [channel], can be a [subscriber], a [publisher] or both_

### Allowed participant
_A [participant] listed as allowed to access a certain [branch]_

### User
_An actor in the Channels messaging protocol_

### Transport
_Transport layer protocol used to deliver [messages]. Currently only Tangle is implemented but other transport protocols are compatible_
### Message
_A cryptographically processed piece of data consisting of a Header and a Content, sent by a [publisher] over the [transport]_

### Link
_Cryptographic mechanism allowing to bind [messages]_

**TODO**: Can we specify what a Link is? What comprises a Link, What is the relationship between a link and a [message address]...

### Message Tree
_Graph with [messages] as nodes and [links] as edges_

### Branch
_Subtree in a [message tree]_

### Chain
_[Branch] that is also a list (ie. each node except for the last one has exactly one child)_

**TODO**: What is the value of listing this concept? Does it provide a distinct practical benefit of considering a particular branch a chain?

### Channel
_A logical collection of linked [messages] that forms a [message tree]_

### Channel Address
_A unique identifier for a [channel]_

**Syn**: `appinst`

### Message ID
_[Message][messages] identifier within a [channel]_

**Alt**: `msgid`

### Message Address
_A unique identifier for a message, consisting in the concatenation of the [channel address] and [message id]_

### Message Index
_A Blake2b256 hash of a [message address] used to reference messages in the [transport]. In the case of the Tangle, this
corresponds to the index in the [`IndexationPayload`] type of message, used to send the Channels [messages]_

### PRNG
_Pseudo-random number generator_

### Transaction
_An IOTA Tangle formatted message_

**TODO**: Is this still valid? Messages are sent as `IndexationPayload`, not as `SignedTransactions`...


## DDML

### Wrap
_Encode some data into a [binary output stream][output stream] while interacting with the [spongos state]_

### Unwrap
_Decode some data from a [binary input stream][input stream] while interacting with the [spongos state]_

### Command
_Construct of the DDML DSL that specifies how a piece of data must be processed when [wrapping] or [unwrapping] it_

### Command Modifier
_Construct of the DDML DSL that customizes the behaviour of a [command]_

### Command block
_Group of [commands][command] that defines a sub-scope for certain [commands][command] like [fork] or [repeated]_
### absorb
_[Command] that writes some data verbatim to the [output stream] when [wrapping] or reads it from the [input stream] when [unwrapping], and in
either case [absorbs][spongos::absorb] the data into the [spongos state]_

### External
_[Command modifier] that instructs the [command] not to touch the [binary stream] and use the data only to interact with the [spongos state]_

### Commit
_[Command] that forces a [commit][spongos::commit] of the current [spongos state]_

### dump
_[Command] that logs the [binary stream] and [spongos state] to stdout for debugging purposes_

### ed25519
_[Command] that [squeezes][squeeze] the hash of the data absorbed so far and either signs it and writes the signature to the [output stream]
when [wrapping] or reads the signature from [input stream] and verifies it when [unwrapping]. Uses an [ed25519 signature key pair][signature key pair] provided as parameter for generating or validating the signature_

### fork
_[Command] that creates a copy of the [spongos state]. This copy is the [spongos state] in scope during the rest of the [command block] and discarded at its end, continuing with the previous [spongos state] afterwards_

### guard
_[Command] that asserts certain condition is true_

### join
_[Command] that fetches a [spongos state] from the [link store] using a [link][ddml::link] makes the current [spongos state]
absorb this second [spongos state]_

### mask
_[Command] that, using the [spongos state] in scope (see [fork]), encrypts some data and writes it to the [output stream] when [wrapping] or reads
it from the [input stream] and decrypts it when [unwrapping]_

### repeated
_[Command] that executes a [command block] once for each item in an iterable_

### skip
_[Command] that either writes some data to the [output stream] when [wrapping] or reads some data from the [input stream] when [unwrapping]
without interating (skipping) the [spongos state]_

### squeeze
_[Command] that squeezes the hash of the data absorbed so far using [spongos::squeeze] and either writes it to the [output stream] when [wrapping]
or reads the same ammount of data from the [input stream] and validates it matches the squeezed hash_

### x25519
_[Command] that performs a Diffie-Hellman exchange and encrypts/decrypts some data, usually used (but not limited to) [cryptographically wrap][key wrapping] a [symmetric encryption key]. When [ddml::wrapping][wrapping], an x25519 [ephemeral key pair] is generated;
the [secret key][ephemeral secret key] is used together with the 3rd-party [static public key][static public key] to compute the
[shared secret][Diffie-Hellman shared secret] resulting from the Diffie-Hellman exchange, which is [spongos::absorbed] by the [spongos state];
the [public key][ephemeral public key] is written to the [output stream] using the [absorb command][absorb]; finally the [Diffie-Hellman shared secret] is
[spongos::absorbed] by the [spongos state] and the arbitrary data is encrypted using the [mask command][mask]. When [unwrapping], the [ephemeral public key]
is read from the [input stream] which is used together with the own [static secret key][static secret key]
to generate the same [Diffie-Hellman shared secret], which is [spongos::absorbed] by the [spongos state] and the arbitrary data is decrypted using the [mask command][mask]_

### Link
_URI of a [spongos state], used to fetch a [spongos state] from the [link store]_

**TODO**: Find a better name that does not collide with channels::Link

### Link Store
_Generic storage of [spongos states][spongos state] indexed by [links][ddml::link]_.

**TODO**: Isn't this more of a State Store?

### Binary Output Stream
_[binary stream] to where data is written when [wrapping]_

### Binary Input Stream
_[binary stream] from where data is read when [unwrapping]_

### Binary Stream
_Unbound sequence of bytes_

### Spongos State
_Data of the [spongos] state-machine that is carried over and modified at the
execution on each [command] (except [skip])_

### Key Agreement Key Pair
_Asymmetric key pair used in a key agreement protocol. A key agreement protocol is a key exchange protocol where all parties contribute equally in the
generation of the [shared secret][Diffie-Hellman shared secret]. Currently DDML uses [x25519 Diffie-Hellman][Diffie-Hellman] as key-agreement protocol._

**Syn**: `Key Exchange Key Pair`
### Ephemeral Key Agreement Key Pair
_[Key agreement key pair][key agreement key pair] generated for a single key agreement_
### Static Key Agreement Key Pair
_Long-lived [key agreement key pair] used in multiple key agreements_
### Ephemeral Key Agreement Public Key
_Public key of an [ephemeral key agreement key pair][ephemeral key pair]_
### Ephemeral Key Agreement Secret Key
_Secret key of an [ephemeral key agreement key pair][ephemeral key pair]_
### Static Key Agreement Public Key
_Public key of an [static key agreement key pair][static key pair]_
### Static Key Agreement Secret Key
_Secret key of an [static key agreement key pair][static key pair]_
### Key Wrapping
_Cryptographic mechanism that encrypts a cryptographic key with another (symmetric) cryptographic key_

### Symmetric Key Wrapping Key
_Symmetric key used to encrypt another key in a [key wrapping] algorithm_
### Symmetric Encryption Key
_Symmetric key used to encrypt arbitrary data_
### Diffie-Hellman Shared Secret
_Symmetric key generated with the [Diffie-Hellman] key agreement protocol. A key agreement protocol is a key exchange protocol where all parties contribute equally in the generation of the shared secret_

**Syn**: `shared_secret`
### Pre-shared Key
_Symmetric key exchanged between parties out-of-band_
### Signature Key Pair
_Asymmetric key pair used for message signature. Currently DDML uses [ed25519 EdDSA] signature scheme_
### Signature Public Key
_Public key of a [signature key pair]_
### Signature Private Key
_Private key of a [signature key pair]_
## Spongos

**TODO**

[user]: #user
[channel]: #channel
[messages]: #message
[allowed participants]: #allowed-participant
[publisher]: #publisher
[subscriber]: #subscriber
[participant]: #participant
[branch]: #branch
[transport]: #transport
[links]: #link
[message tree]: #message-tree
[channel address]: #channel-address
[message id]: #message-id
[message address]: #message-address
[`IndexationPayload`]: https://chrysalis.docs.iota.org/guides/dev_guide#indexationpayload
[spongos state]: #spongos-state
[output stream]: #binary-output-stream
[input stream]: #binary-input-stream
[binary stream]: #binary-stream
[wrapping]: #wrap
[unwrapping]: #unwrap
[command]: #command
[command modifier]: #command-modifier
[command block]: #command-block
[absorb]: #absorb
[mask]: #mask
[external]: #external
[fork]: #fork
[repeated]: #repeated
[squeeze]: #squeeze
[skip]: #skip
[ddml::link]: #link-1
[link store]: #link-store
[key wrapping]: #key-wrapping
[symmetric encryption key]: #symmetric-encryption-key
[key agreement key pair]: #key-agreement-key-pair
[ephemeral key pair]: #ephemeral-key-agreement-key-pair
[static key pair]: #static-key-agreement-key-pair
[ephemeral public key]: #ephemeral-key-agreement-public-key
[ephemeral secret key]: #ephemeral-key-agreement-secret-key
[static public key]: #static-key-agreement-public-key
[static secret key]: #static-key-agreement-secret-key
[Diffie-Hellman shared secret]: #diffie-hellman-shared-secret
[Diffie-Hellman]: https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange
[ed25519 EdDSA]: https://en.wikipedia.org/wiki/EdDSA#Ed25519
[signature key pair]: #signature-key-pair

---
# Backlog
## Traits
### Channels
ContentSizeof
ContentUnwrap
ContentUnwrapNew
ContentWrap
HasLink
KeyStore
LinkedMessage
LinkGenerator
Transport
TransportDetails
TransportOptions
TrustProvider

### DDML
Absorb
AbsorbExternalFallback
AbsorbFallback
Commit
Dump
Ed25519
Fork
Guard
IStream
Join
LinkStore
Mask
OStream
Repeated
Skip
SkipFallback
Squeeze
Unwrap
Wrap
X25519

### Spongos
Hash
PRP

## structs
### Channels
a
absolute
Address
AppInst
Author
BinaryBody
BucketTransport
Buffer
CargoTarget
Client
Content
ContentUnwrap
ContentWrap
Cursor
DefaultTangleLinkGenerator
Details
GeneratorSharedArgs
GenericMessage
HDF
KeyMap
Message
MessageLinks
MessageMetadata
Milestone
MilestoneResponse
MsgId
NextMsgId
PacketPayloads
PCF
Platform
PreparedMessage
PreparsedMessage
PskIds
PublicKeys
SendOptions
Streams
Subscriber
TangleAddress
TangleMessage
TransportDetails
UnwrappedMessage
User
UserResponse
UserState
WrappedMessage
WrappedSequence
WrapState
WrapStateSequence

### DDML
AbsorbContext
AbsorbExternalContext
Bytes
Context
DefaultLinkStore
EmptyLinkStore
External
Fallback
HashSig
Mac
MaskContext
NBytes
Prehashed
SingleLinkStore
Size
SkipContext
TestAbsLink
TestMessage
TestMessageInfo
TestRelLink
TestStore
Uint16
Uint32
Uint64
Uint8
WrapCtx

### Spongos
FixedRng
Inner
KeccakF1600
PrivateKey
Prng
PublicKeyWrap
Rng
Spongos
state
WrappedError
X

## enums

### Channels
CargoTargetType
ChannelType
Err
Identifier
LedgerInclusionState
MessageContent
MsgInfo

### DDML

### Spongos
crates
Errors

## aliases
### Channels
Address
AppInstSize
as
Author
Base
BinaryMessage
BucketTransport
ChannelAddress
ClientWrap
containing
DefaultF
Details
Err
Error
for
from
in
indicator
is
KePks
KeyStore
LinkGen
LinkStore
Message
MsgIdSize
NextMsgIds
of
Preparsed
PskIds
PublicKey
RecvOptions
Rel
Result
SendOptions
SeqState
SharedTransport
Subscriber
to
TransportWrap
UnwrappedMessage
UnwrappedMessages
UserImp
UserState
with
WrappedMessage
WrappedSequence
WrapState
WrapStateSequence

### DDML
Info
is
N
of
or
OutputSize

### Spongos
CapacitySize
HashSize
in
IPk
IPsk
is
Key
KeySize
KeyType
MacSize
Nonce
NonceSize
NonceType
not
OutputSize
Pks
Psk
PskId
PskIds
PskIdSize
Psks
PskSize
PublicKeySize
RateSize
synonym

## Variables

### Channels
_
a
addr_vec
ann
announcement_link
appinst
args
author
_author2
authordump
author_sig_pk
_b
binary
binary_root
body
branching
buf_size
bytes
bytes_vec
cargo_executable
cargo_platform
cargo_target
cargo_version
channel_idx
channel_impl
client
config_folder
config_root
config_type
content
content_type_and_payload_length
crates
ctx
current_dir
cursor
dst
e
exe_file
extra_link_args
field_flags
file
flags
g
hash
has_pdb
header
id
identifier
Identifier
identifiers
ids
ike_pks
imported_implib
imported_location
ke_kp
ke_pk
key
keyload_link
keys
languages
libraries
link
linker_arg
links
link_store
link_vec
m
mac
manifest_path
masked_payload
matches
message
metadata
metadata_manifest_path
msg
msg_id
msgid
msg_ids
msg_link
msgs
mut
n
name
next_msg_ids
next_msgs
nonce
Ok
oneof
oneof_appinst
oneof_author_sig_pk
p
package2
path
payload_frame_count
payload_frame_num
payloads
pks
pk_str
preference
prefix
prepared
preparsed
previous_msg_link
prev_link
prev_msg
prev_msg_link
prng
processed
psk
pskid
pskid_str
psks
public_payload
_r
r
ref_link
repeated_keys
repeated_links
responses
resultA
resultB
retrieved
s
search_dirs
sender_id
send_opt
seq
seq_link
seq_msg
seq_no
shared_args
sig_kp
signed_packet_link
sig_pk
sig_sk
Some
spongos
state_list
store
store_id
subAdump
subBdump
subscribeB_link
subscriber
_subscriberA2
_subscriberB2
subscriber_sig_pk
suffix
tagged_packet_link
target
targets
target_type
timestamp
total
transport
tx_address
tx_tag
u
unsubscribe_key
unwrapped
url
user
v
wrapped
x

### DDML
buf_size
buf_size2
context
d
enta
ephemeral_ke_pk
ephemeral_ke_sk
i
inner
key
kp
mac
msg
mut
n
None
ns
nta
ntm
prng
public
public_a
public_b
r
s
saved_fork
secret
secret_a
secret_b
shared
signature
size
slice
Some
t
ta
tm
y

### Spongos
dex
ed_kp
ex
i
k
key
m
mut
n
p
pk
pskid_bytes
ptr
rate
s
sk
t
t2
t3
tag
u
x
x1B
x1KiB
x1MiB
x5KiT
x5MiT
x5T
x_kp
x_pk2
y

## functions & methods

### Channels
add
address_from_string
addr_id
alloc_error
announce
as_mut
as_ref
async_get_link_details
async_recv_messages
async_send_message_with_options
auth_channel_address
auth_drop
auth_export
auth_fetch_next_msgs
auth_fetch_prev_msg
auth_fetch_prev_msgs
auth_fetch_state
auth_gen_next_msg_ids
auth_get_public_key
auth_import
auth_is_multi_branching
auth_new
author_public_key
auth_receive_msg
auth_receive_sequence
auth_receive_signed_packet
auth_receive_subscribe
auth_receive_tagged_packet
auth_recover
auth_send_announce
auth_send_keyload
auth_send_keyload_for_everyone
auth_send_signed_packet
auth_send_tagged_packet
auth_store_psk
auth_sync_state
base
build_script
channel_address
check_content_type
check_trusted
__chkstk
clone
commit
commit_sequence
commit_wrapped
contains
content_type
copy
cpp_function
create_channel
default
default_with_content
do_prepare_keyload
drop
drop_address
drop_buffer
drop_links
drop_next_msg_ids
drop_payloads
drop_pskid
drop_str
drop_unwrapped_message
drop_unwrapped_messages
drop_user_state
dynamic_lib_name
eh_personality
emit_cmake_config_info
emit_cmake_target
ensure_appinst
eq
error
example
exe_name
export
fetch_all_next_msgs
fetch_next_msgs
fetch_prev_msg
fetch_prev_msgs
fetch_state
filter
fmt
from
from_base_rel
from_bytes
from_client
from_c_str
from_metadata
from_rust_version_target
from_str
from_string
from_strings
gen
gen_msgid
gen_next_msg_id
gen_next_msg_ids
gen_uniform_msgid
get
get_address_id_str
get_address_index_str
get_address_inst_str
get_branch_no
get_channel_address_str
get_channel_type
get_client
get_content_type
get_hash
get_identifier
get_ids
get_indexed_payload
get_ke_pk
get_link
get_link_details
get_link_from_state
get_masked_payload
get_message
get_message_contents
get_messages
get_metadata
get_milestone
get_msgid_str
get_msg_link
get_mut
get_next_pskid
get_parent_message_ids
get_payload
get_payload_frame_count
get_payload_frame_num
get_payload_length
get_payloads_count
get_pk
get_pks
get_previous_msg_link
get_psk
get_public_key
get_public_payload
get_recv_options
get_send_options
get_seq_link
get_seq_no
get_seq_num
get_transport
greeting
handle_announcement
handle_client_result
handle_keyload
handle_message
handle_message_contents
handle_sequence
handle_signed_packet
handle_subscribe
handle_tagged_packet
hash
header_from
identifier_to_string
implib_name
import
insert_cursor
insert_psk
into_seq_link
invoke
is_corrosion_build
is_macos
is_msvc
is_multi_branching
is_registered
is_single_depth
is_windows
is_windows_gnu
iter
iter_mut
it_works
keys
lib_name
link
link_from
log
lookup_ke_sk
lookup_psk
main
map
map_err
memcmp
memcpy
memmove
memset
message_id
minmain
msg_from_tangle_message
msg_id
new
new_announce
new_at
new_final_frame
new_from_url
new_init_frame
new_inter_frame
new_keyload
new_shared_transport
new_signed_packet
new_tagged_packet
new_with_fields
next_branch
next_seq
panic
parse_header
parse_msg_info
payload_frame_num_check
payload_frame_num_from
payload_frame_num_to
pdb_name
prepare_announcement
prepare_keyload
prepare_keyload_for_everyone
prepare_sequence
prepare_signed_packet
prepare_subscribe
prepare_tagged_packet
prev_link
process_sequence
psk_from_seed
pskid_as_str
pskid_from_psk
pskid_from_seed
pskid_from_str
public_key_from_string
public_key_to_string
receive_announcement
receive_keyload
receive_message
receive_msg
receive_sequence
receive_signed_packet
receive_subscribe
receive_tagged_packet
receive_unsubscribe
recover
recv_message
recv_messages
rel
reset
reset_addr
reset_state
run_basic_scenario
rust_function
safe_drop_mut_ptr
safe_drop_ptr
safe_into_mut_ptr
safe_into_ptr
send_announce
send_keyload
send_keyload_for_everyone
send_message
send_message_sequenced
send_sequence
send_signed_packet
send_subscribe
send_tagged_packet
set_addr_id
set_msg_id
set_panic_hook
set_recv_options
set_send_options
set_seq_num
set_state
set_url
share_keyload
share_keyload_for_everyone
sign_packet
sizeof
sizeof_absorb
sizeof_absorb_external
sizeof_skip
static_lib_name
store_psk
store_state
store_state_for_all
sub_author_public_key
sub_channel_address
subcommand
sub_drop
sub_export
sub_fetch_next_msgs
sub_fetch_prev_msg
sub_fetch_prev_msgs
sub_fetch_state
sub_gen_next_msg_ids
sub_get_public_key
sub_import
sub_is_multi_branching
sub_is_registered
sub_new
sub_receive_announce
sub_receive_keyload
sub_receive_keyload_from_ids
sub_receive_msg
sub_receive_sequence
sub_receive_signed_packet
sub_receive_tagged_packet
sub_recover
sub_reset_state
subscribe
sub_send_signed_packet
sub_send_subscribe
sub_send_tagged_packet
sub_store_psk
sub_sync_state
sub_unregister
sync_get_link_details
sync_recv_messages
sync_send_message_with_options
sync_state
tag_packet
to_bytes
to_inner
to_result
to_string
transport_client_new_from_url
transport_drop
transport_get_link_details
transport_new
try_from
uniform_header_from
uniform_link_from
unreadable
unregister
unsubscribe
unwrap
unwrap_absorb
unwrap_absorb_external
unwrap_announcement
unwrap_keyload
unwrap_new
unwrap_sequence
unwrap_signed_packet
unwrap_skip
unwrap_subscribe
unwrap_tagged_packet
url
WinMain
WinMainCRTStartup
with_content
with_content_type
with_cursor
with_identifier
with_payload_frame_count
with_payload_frame_num
with_payload_length
with_previous_msg_link
with_seq_num
with_state
with_timestamp
with_wrapped
wrap
wrap_absorb
wrap_absorb_external
wrap_sequence
wrap_skip

### DDML
absorb
absorb_ed25519
absorb_mask_size
absorb_mask_squeeze_bytes_mac
absorb_mask_u8
advance
as_mut
as_mut_slice
as_ref
as_slice
bytes
chain
clone
commit
default
digest
drop
dump
ed25519
eq
erase
finalize
finalize_reset
fmt
fork
from
get_size
guard
hash
info
insert
into
iter
join
join_link
link
lookup
mask
new
output_size
repeated
reset
run_join_link
size
size_bytes
sizeof_absorb
sizeof_absorb_external
sizeof_sizet
sizeof_skip
skip
spongos
squeeze
test_ed25519
test_u8
test_x25519
try_advance
unwrap
unwrap_absorb
unwrap_absorb_bytes
unwrap_absorb_external
unwrap_absorb_size
unwrap_absorb_u16
unwrap_absorb_u32
unwrap_absorb_u64
unwrap_absorb_u8
unwrap_mask_bytes
unwrap_mask_size
unwrap_mask_u16
unwrap_mask_u32
unwrap_mask_u64
unwrap_mask_u8
unwrapn
unwrap_size
unwrap_skip
unwrap_skip_bytes
unwrap_skip_size
unwrap_skip_u16
unwrap_skip_u32
unwrap_skip_u64
unwrap_skip_u8
unwrap_u16
unwrap_u32
unwrap_u64
unwrap_u8
update
wrap
wrap_absorb
wrap_absorb_bytes
wrap_absorb_external
wrap_absorb_external_bytes
wrap_absorb_external_size
wrap_absorb_external_u16
wrap_absorb_external_u32
wrap_absorb_external_u64
wrap_absorb_external_u8
wrap_absorb_size
wrap_absorb_u16
wrap_absorb_u32
wrap_absorb_u64
wrap_absorb_u8
wrap_mask_bytes
wrap_mask_size
wrap_mask_u16
wrap_mask_u32
wrap_mask_u64
wrap_mask_u8
wrapn
wrap_size
wrap_skip
wrap_skip_size
wrap_skip_trits
wrap_skip_u16
wrap_skip_u32
wrap_skip_u64
wrap_skip_u8
wrap_u16
wrap_u32
wrap_u64
wrap_u8
x25519
x25519_ephemeral
x25519_static
x25519_transport

### Spongos
absorb
arr
arr_mut
as_mut
as_ref
basic_ftroika
bytes_spongosn
bytes_with_size_boundary_cases
chain
commit
copy
dbg_init_str
decrypt
decrypt_arr
decrypt_mut
decrypt_n
decrypt_xor
decrypt_xor_mut
default
digest
done
done_bytes
encrypt
encrypt_arr
encrypt_decrypt_keccak_byte
encrypt_decrypt_n
encrypt_mut
encrypt_n
encrypt_xor
encrypt_xor_mut
eq
equals
err
fill_bytes
filter_ke_pks
filter_psks
finalize
finalize_reset
fmt
fork
fork_at
from
from_inner
from_seed
ftroika_benchmark
gen
gen_arr
gen_n
gen_with_spongos
hash
hash_bytes
hash_data
inc
init
init_with_seed
init_with_state
inner
is_committed
join
keccakf1600b_benchmark
keccakf1600_benchmark
keccakf1600t_benchmark
key_from_seed
keypair_from_ed25519
new
next_u32
next_u64
outer
outer_min_mut
outer_mut
output_size
panic_if_not
permutation
psk_from_seed
pskid_from_hex_str
pskid_from_psk
pskid_from_seed
pskid_from_str
pskid_to_hex_string
public_from_ed25519
random_bytes
random_key
random_nonce
rehash
rehash_bytes
reset
slice_spongosn
slices_with_size_boundary_cases
slices_with_size_boundary_cases_keccak_byte
squeeze
squeeze_arr
squeeze_eq
squeeze_n
step
tbits_with_size_boundary_cases_keccak_byte
test_25519
test_25519_fixed
test_25519_thread_rng
to_inner
transform
try_fill_bytes
try_or
update
update_bytes
wrapped_err
xor

### parameters and fields

#### Channels
0
1
2
a
AbsLink
addr
addr_id
addr_vec
ALLOC
ANN_MESSAGE_NUM
ANNOUNCE
announcement_link
appinst
APPINST_SIZE
author
author_sig_pk
_b
b
Base
binary
body
Body
branching
branch_no
bucket
buffer
bytes
bytes_vec
cap
cargo_executable
cargo_package
cargo_target
cases
channel_idx
channel_type
Characters
client
conflict_reason
content
Content
content_type
ctx
cursor
d
details
e
E
encoding
error
f
F
field_flags
FINAL_PCF_ID
flag
FLAG_BRANCHING_MASK
flags
frame_type
H
has_cdylib
HasLink
has_staticlib
HDF_ID
header
highest_preference
i
id
identifier
identifiers
ids
idx
implementation
index
info
Info
INIT_PCF_ID
instance
INTER_PCF_ID
IS
is_multi_config
is_solid
ke_pk
ke_pks
KePks
key
key_ids
KEYLOAD
keys
Keys
key_store
languages
layer
ledger_inclusion_state
LG
libraries
libs
libs_debug
libs_release
link
Link
link_gen
links
link_store
link_to
link_vec
local_pow
lookup_ke_sk
LookupKeSk
lookup_psk
LookupPsk
LS
m
manifest_path
masked_payload
masked_payload_size
max
message
message_encoding
message_id
metadata
milestone
milestone_index
msg
Msg
msg0
msg_id
msgid
MSGID_SIZE
msg_link
msgs
_n
n
node
nonce
num_msgs
opt
options
OS
out_file
parent_message_ids
PAYLOAD_BYTES
payload_frame_count
payload_frame_num
payload_length
PAYLOAD_LENGTH
payloads
pcf
_phantom
pk
pks
preparsed
previous_msg_link
prev_link
prng
psk
pskid
psk_ids
psks
psk_seed_str
ptr
public
public_payload
public_payload_size
r
referenced_by_milestone_index
Rel
Removed
restrictive
result
retrieved
roles
search_dirs
secret
seed
Self
sender_id
send_opt
seq_link
SEQ_MESSAGE_NUM
seq_no
seq_num
SEQUENCE
should_promote
should_reattach
sig_kp
SIGNED_PACKET
sig_pk
sig_pks
size
spongos
state
store
Store
STREAMS_1_VER
SUB_MESSAGE_NUM
SUBSCRIBE
subscriber
subscriber_sig_pk
supported
T
TAGGED_PACKET
targets
target_type
timestamp
TODO
Trans
transport
Transport
tsp
Tsp
TW
uniform_payload_length
UNSUBSCRIBE
unsubscribe_key
url
use_psk
user
UTF8
_val
val
value
vec
verbose
version
VERSION
WARNING
wrapped
x

#### DDML

a
AbsLink
addr
args
ArrayType
bytes
C
cell1
cell2
cell3
change
cond
cont
ctx
_data
err
_external
external_nbytes
external_ntrytes
F
field
ga
H
_hash
hash
i
I
_info
info
Info
inner
IS
key
L
link
Link
map
masked
n
N
nbytes
OS
_phantom
pk
RelLink
s
S
Self
size
sk
_spongos
spongos
ss
store
stream
t
TODO
trytes
u
val
value_handle
values_iter

#### Spongos
bytes
CapacitySize
cond
data
err
expected
F
found
G
H
Hash
HASH_SIZE
inner
KEY_SIZE
LOCATION_LOG
MAC_SIZE
n
N
nonce
Output
_phantom
pk
pos
preparation
prng
PRP
PSKID_SIZE
PSK_SIZE
PUBLIC_KEY_LENGTH
R
RateSize
rnd
s
secret_key
seed
src
t
T
t2
t3
TODO
u
x
xr
xyr
y
yr
z
