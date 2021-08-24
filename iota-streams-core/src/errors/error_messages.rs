use crate::prelude::String;
use core::fmt::Debug;

use displaydoc::Display;

pub struct WrappedError<T: Debug>(pub T);

#[derive(Display, Debug)]
pub enum Errors {
    //////////
    // Generic
    //////////
    /// Max size exceeded (expected: {0}, found: {1})
    MaxSizeExceeded(usize, usize),
    /// Value out of range (max: {0}, index: {1})
    ValueOutOfRange(usize, usize),
    /// Value does not match (expected: {0}, found: {1})
    ValueMismatch(usize, usize),
    /// Size of vec/array does not match (expected: {0}, found: {1})
    LengthMismatch(usize, usize),
    /// Spongos is not committed, outer position is not 0
    SpongosNotCommitted,
    /// Link not found in store. (Possibly unimplemented)
    GenericLinkNotFound,
    /// Unexpected/invalid Identifier
    BadIdentifier,
    /// Psk has already been stored
    PskAlreadyStored,
    /// Input string {0} is not in hex format
    BadHexFormat(String),

    //////////
    // Cryptographic
    //////////
    /// Failed to convert ed25519 public key to x25519 public key
    KeyConversionFailure,

    //////////
    // DDML Wrap/Unwrap
    //////////
    /// There was an issue with the calculated signature, cannot unwrap message
    SignatureMismatch,
    /// There was an issue with calculating the signature, cannot wrap message.
    SignatureFailure,
    /// Failure to generate ed25519 public key
    PublicKeyGenerationFailure,
    /// Failure to generate x25519 public key
    XPublicKeyGenerationFailure,
    /// Integrity violation. Bad MAC
    BadMac,
    /// No default Random Number Generator available for no_std usage
    NoStdRngMissing,
    /// Oneof value is unexpected
    BadOneof,

    //////////
    // DDML IO
    //////////
    /// Not enough space allocated for output stream (expected: {0}, found: {1})
    StreamAllocationExceededOut(usize, usize),
    /// Not enough space allocated for input stream (expected: {0}, found: {1})
    StreamAllocationExceededIn(usize, usize),
    /// Output stream has not been exhausted. Remaining: {0}
    OutputStreamNotFullyConsumed(usize),
    /// Input stream has not been exhausted. Remaining: {0}
    InputStreamNotFullyConsumed(usize),

    //////////
    // Generic Transport
    //////////
    /// More than one message found: with link {0}
    MessageNotUnique(String),
    /// Message at link {0} not found in store
    MessageLinkNotFound(String),
    /// Message at link {0} not found in tangle
    MessageLinkNotFoundInTangle(String),
    /// Transport object is already borrowed
    TransportNotAvailable,

    //////////
    // Iota Transport
    //////////
    /// Malformed address string: missing colon (':') separator between appinst and msgid
    MalformedAddressString,

    //////////
    // Iota Client
    //////////
    /// Iota Message Address failed to generate. // UNUSED
    BadTransactionAddress,
    /// Iota Message Tag failed to generate. // UNUSED
    BadTransactionTag,
    /// Message index not found
    IndexNotFound,
    /// Message data not found
    MessageContentsNotFound,
    /// Iota Message failed to generate. // UNUSED
    BadMessageTimestamp,
    /// Iota Message Payload failed to generate.
    BadMessagePayload,
    /// Iota Message failed to seal. // UNUSED
    MessageSealFailure,
    /// Iota Message failed to attach. // UNUSED
    MessageAttachFailure,
    /// Iota Message failed to build. // UNUSED
    MessageBuildFailure,
    /// Iota Client failed to perform operation.
    ClientOperationFailure,

    //////////
    // Messages
    //////////
    /// Message version not supported (expected: {0}, found: {1})
    InvalidMsgVersion(u8, u8),
    /// Message frame type not supported (expected: {0}, found: {1})
    InvalidMsgType(u8, u8),
    /// Message type is not known (found: {0})
    UnknownMsgType(u8),
    /// Reserved bits are improperly formatted
    InvalidBitReservation,
    /// Message is not an announcement (found: {0})
    NotAnnouncement(u8),
    /// Message info provided is not registered (found: {0})
    BadMessageInfo(u8),
    /// Failed to make message
    MessageCreationFailure,
    /// Identifier could not be generated with given bytes. Must be an ed25519 Public Key or a PskId
    IdentifierGenerationFailure,

    //////////
    // Users
    //////////
    /// Cannot create a channel, user is already registered to channel {0}
    ChannelCreationFailure(String),
    /// Cannot unwrap announcement message, already registered to channel {0}
    UserAlreadyRegistered(String),
    /// User is not registered to a channel
    UserNotRegistered,
    /// Message application instance does not match user channel (expected: {0}, found: {1}
    MessageAppInstMismatch(String, String),
    /// Author public x25519 exchange key not found in user instance
    AuthorExchangeKeyNotFound,
    /// Author public ed25519 signature key not found in user instance
    AuthorSigKeyNotFound,
    /// Error retrieving sequence number for message preparation: No sequence number generated
    SeqNumRetrievalFailure,
    /// State store has failed to retrieve
    StateStoreFailure,
    /// Cannot generate new channel, it may already exists. please try using a different seed
    ChannelDuplication,
    /// Subscriber already has a psk stored, cannot add another
    SinglePskAllowance,

    //////////
    // User Recovery
    //////////
    /// Application Instance recovery failed (expected: 0 | 1, found: {0})
    AppInstRecoveryFailure(u8),
    /// Author signature pubkey recovery failed (expected: 0 | 1, found: {0})
    AuthorSigPkRecoveryFailure(u8),
    /// User Version does not match (expected: {0}, found: {1}
    UserVersionRecoveryFailure(u8, u8),
    /// Recovered flag does not match expected: flag (expected: {0}, found: {1})
    UserFlagRecoveryFailure(u8, u8),

    //////////
    // Examples
    //////////
    /// Public Payload does not match (expected: {0}, found: {1})
    PublicPayloadMismatch(String, String),
    /// Public Payload does not match (expected: {0}, found: {1})
    MaskedPayloadMismatch(String, String),
    /// Branching flag for subscriber {0} should match authors branching flag
    BranchingFlagMismatch(String),
    /// Channel Application Instance for subscriber {0} should match authors.
    ApplicationInstanceMismatch(String),
    /// Channel Application Instance for subscriber {0} should match announcement.
    ApplicationInstanceAnnouncementMismatch(String),
    /// Subscriber {0} should not be able to access this message
    SubscriberAccessMismatch(String),
    /// Expected Link does not match (expected: {0}, found {1})
    LinkMismatch(String, String),
    /// States do not match
    StateMismatch,

    //////////
    // Tests
    //////////
    /// Bytes are invalid. Values don't match (expected {0}, found {1}
    InvalidBytes(String, String),
    /// Squeezed tag is invalid. Unwrapped tag doesn't match (expected {0}, found {1}
    InvalidTagSqueeze(String, String),
    /// Squeezed hash is invalid. Unwrapped hash doesn't match (expected {0}, found {1}
    InvalidHashSqueeze(String, String),
    /// Squeezed key is invalid. Unwrapped key doesn't match (expected {0}, found {1}
    InvalidKeySqueeze(String, String),
    /// Subscriber {0} failed to unwrap message, may not have access to branch
    MessageUnwrapFailure(String),
}
