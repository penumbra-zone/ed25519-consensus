#![doc(html_root_url = "https://docs.rs/ed25519-zebra/2.2.0")]
#![cfg_attr(feature = "nightly", feature(doc_cfg))]
#![cfg_attr(feature = "nightly", feature(external_doc))]
#![cfg_attr(feature = "nightly", doc(include = "../README.md"))]
#![deny(missing_docs)]

//! Docs require the `nightly` feature until RFC 1990 lands.

pub mod batch;
mod error;
mod signature;
mod signing_key;
mod verification_key;

pub use error::Error;
pub use signature::Signature;
pub use signing_key::SigningKey;
pub use verification_key::{VerificationKey, VerificationKeyBytes};
