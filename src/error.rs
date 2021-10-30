#[cfg(feature = "std")]
use thiserror::Error;

/// An error related to Ed25519 signatures.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "std", derive(Error))]
pub enum Error {
    /// The encoding of a secret key was malformed.
    #[cfg_attr(feature = "std", error("Malformed secret key encoding."))]
    MalformedSecretKey,
    /// The encoding of a public key was malformed.
    #[cfg_attr(feature = "std", error("Malformed public key encoding."))]
    MalformedPublicKey,
    /// Signature verification failed.
    #[cfg_attr(feature = "std", error("Invalid signature."))]
    InvalidSignature,
    /// A byte slice of the wrong length was supplied during parsing.
    #[cfg_attr(feature = "std", error("Invalid length when parsing byte slice."))]
    InvalidSliceLength,
}
