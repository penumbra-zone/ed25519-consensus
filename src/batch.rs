//! Composable, futures-based batch verification.
//! 
//! This is an experimental interface meant to explore a new programming
//! model for batch verification of heterogeneous data, using Ed25519
//! signatures as a testing ground.  Conventional batch verification
//! APIs require choosing in advance how much data to batch, and then
//! processing the entire batch simultaneously.  But for applications
//! which require verification of heterogeneous data, this is cumbersome
//! and difficult.
//!
//! For example, Zcash uses four different kinds of signatures (ECDSA
//! signatures from Bitcoin, Ed25519 signatures for Sprout, and
//! RedJubjub spendauth and binding signatures for Sapling) as well as
//! three different kinds of zero-knowledge proofs (Sprout-on-BCTV14,
//! Sprout-on-Groth16, and Sapling-on-Groth16).  A single transaction
//! can have multiple proofs or signatures of different kinds, depending
//! on the transaction version and its structure.  Verification of a
//! transaction conventionally proceeds “depth-first”, checking that the
//! structure is appropriate and then that all the component signatures
//! and proofs are valid.
//!
//! Now consider the problem of implementing batch verification in this
//! context, using conventional batch verification APIs that require
//! passing a list of signatures or proofs.  This is quite complicated,
//! requiring implementing a second transposed set of validation logic
//! that proceeds “breadth-first”, checking that the structure of each
//! transaction is appropriate while assembling collections of
//! signatures and proofs to verify.  This transposed validation logic
//! must match the untransposed logic, but there is another problem,
//! which is that the set of transactions must be decided in advance.
//! This is difficult because different levels of batching are required
//! in different contexts.  For instance, batching within a transaction
//! is appropriate on receipt of a gossiped transaction, batching within
//! a block is appropriate for block verification, and batching across
//! blocks is appropriate when syncing the chain.
//!
//! ## Verification Futures
//!
//! To address this problem, we move from a synchronous model for
//! signature verification to an asynchronous model.  Rather than
//! immediately returning a verification result, verification returns a
//! future which will eventually resolve to a verification result.
//! Verification futures can be combined with various futures
//! combinators, expressing the logical semantics of the combined
//! verification checks.  This allows writing checks generic over the
//! choice of singleton or batched verification.  And because the batch
//! context is distinct from the verification logic itself, the same
//! verification logic can be reused in different batching contexts -
//! batching within a transaction, within a block, within a chain, etc.
//!
//! ## Examples
//! 
//! TODO: add once API is more well-formed.

mod batcher;
mod singleton;

pub use batcher::BatchVerifier;
pub use singleton::SingletonVerifier;

use super::{PublicKeyBytes, Signature};

/// A type alias for a batch verification request.
pub type VerificationRequest<'msg> = (PublicKeyBytes, Signature, &'msg [u8]);
