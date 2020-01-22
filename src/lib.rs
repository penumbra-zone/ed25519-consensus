// Uncomment this before publication.
//#![doc(html_root_url = "https://docs.rs/ed25519-zebra/0.1.0")]
#![cfg_attr(feature = "nightly", feature(external_doc))]
#![cfg_attr(feature = "nightly", doc(include = "../README.md"))]
#![deny(missing_docs)]

//! Docs require the `nightly` feature until RFC 1990 lands.

mod error;
mod public_key;
mod secret_key;
mod signature;

pub use error::Error;
pub use public_key::{PublicKey, PublicKeyBytes};
pub use secret_key::SecretKey;
pub use signature::Signature;
