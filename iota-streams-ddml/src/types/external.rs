/// DDML `external` modifier, it changes behaviour of commands in the following way.
/// The external field is not encoded in binary representation and the value is stored in the environment implicitly.
#[derive(PartialEq, Eq, Copy, Clone, Debug, Default)]
pub struct External<T>(pub T);
