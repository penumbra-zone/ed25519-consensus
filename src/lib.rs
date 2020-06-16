#![doc(html_root_url = "https://docs.rs/ed25519-zebra/0.2.3")]
#![cfg_attr(feature = "nightly", feature(doc_cfg))]
#![cfg_attr(feature = "nightly", feature(external_doc))]
#![cfg_attr(feature = "nightly", doc(include = "../README.md"))]
#![deny(missing_docs)]

//! Docs require the `nightly` feature until RFC 1990 lands.

mod batch;
mod constants;
mod error;
mod public_key;
mod secret_key;
mod signature;

pub use batch::BatchVerifier;
pub use error::Error;
pub use public_key::{PublicKey, PublicKeyBytes};
pub use secret_key::SecretKey;
pub use signature::Signature;
