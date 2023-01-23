#![doc(html_root_url = "https://docs.rs/ed25519-consensus/2.1.0")]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
pub mod batch;
mod error;
mod signing_key;
mod verification_key;

pub use ed25519::{signature, Signature};
pub use error::Error;
pub use signing_key::SigningKey;
pub use verification_key::{VerificationKey, VerificationKeyBytes};
