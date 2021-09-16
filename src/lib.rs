#![doc(html_root_url = "https://docs.rs/ed25519-consensus/1.0.0")]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

pub mod batch;
mod error;
mod signature;
mod signing_key;
mod verification_key;

pub use error::Error;
pub use signature::Signature;
pub use signing_key::SigningKey;
pub use verification_key::{VerificationKey, VerificationKeyBytes};
