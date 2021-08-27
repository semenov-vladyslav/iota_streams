/// The value wrapped in Mac is just the size of message authentication tag (MAC) in bytes.
/// The actual bytes are not important. The requested amount of bytes is squeezed
/// from Spongos and encoded in the binary stream during Wrap operation.
/// During Unwrap operation the requested amount of bytes is squeezed from Spongos
/// and compared to the bytes encoded in the binary stream.
#[derive(PartialEq, Eq, Copy, Clone, Debug)]
pub struct Mac(pub usize);
