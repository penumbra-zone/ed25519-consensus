//! Composable, futures-based batch verification.

mod batcher;
mod singleton;

pub use batcher::BatchVerifier;

use super::{PublicKeyBytes, Signature};

/// A type alias for a batch verification request.
pub type VerificationRequest<'msg> = (PublicKeyBytes, Signature, &'msg [u8]);
