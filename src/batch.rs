use std::collections::HashMap;

use curve25519_dalek::{
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    traits::{IsIdentity, VartimeMultiscalarMul},
};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};

use crate::{Error, PublicKeyBytes, Signature};

// Shim to generate a u128 without importing `rand`.
fn gen_u128<R: RngCore + CryptoRng>(mut rng: R) -> u128 {
    let mut bytes = [0u8; 16];
    rng.fill_bytes(&mut bytes[..]);
    u128::from_le_bytes(bytes)
}

/// Performs batch Ed25519 signature verification.
///
/// Batch verification asks whether *all*
/// signatures in some set are valid, rather than asking whether *each* of them
/// is valid. This allows sharing computations among all signature verifications,
/// performing less work overall at the cost of higher latency (the entire batch
/// must complete), complexity of caller code (which must assemble a batch of
/// signatures across work-items), and loss of the ability to easily pinpoint
/// failing signatures.
///
/// In addition to these general tradeoffs, design flaws in Ed25519 specifically
/// mean that batched verification may not agree with individual verification.
/// Some signature may verify as part of a batch but not on its own. In
/// particular, this batching implementation does not perform the same
/// verification checks as the standalone implementation in this crate. **It
/// should therefore not be used in consensus-critical applications.**
///
/// This batch verification implementation is adaptive in the sense that it
/// detects multiple signatures created with the same public key and
/// automatically coalesces terms in the final verification equation. In the
/// limiting case where all signatures in the batch are made with the same public
/// key, coalesced batch verification runs twice as fast as ordinary batch
/// verification.
///
/// ![benchmark](https://www.zfnd.org/images/coalesced-batch-graph.png)
///
/// This optimization doesn't help much with Zcash, where public
/// keys are random, but could be useful in proof-of-stake systems where
/// signatures come from a set of validators (except for the consensus behavior
/// described above, which will be addressed in a future version of this
/// library).
///
/// # Example
/// ```
/// # use ed25519_zebra::*;
/// let mut batch = BatchVerifier::new();
/// for _ in 0..32 {
///     let sk = SecretKey::new(rand::thread_rng());
///     let pk_bytes = PublicKeyBytes::from(&sk);
///     let msg = b"BatchVerifyTest";
///     let sig = sk.sign(&msg[..]);
///     batch.queue(pk_bytes, sig, &msg[..]);
/// }
/// assert!(batch.verify(rand::thread_rng()).is_ok());
/// ```
#[derive(Default)]
pub struct BatchVerifier {
    /// Signature data queued for verification.
    signatures: HashMap<PublicKeyBytes, Vec<(Scalar, Signature)>>,
    /// Caching this count avoids a hash traversal to figure out
    /// how much to preallocate.
    batch_size: usize,
}

impl BatchVerifier {
    /// Construct a new batch verifier.
    pub fn new() -> BatchVerifier {
        BatchVerifier::default()
    }

    /// Queue a (key, signature, message) tuple for verification.
    pub fn queue(&mut self, pk_bytes: PublicKeyBytes, sig: Signature, msg: &[u8]) {
        // Compute k now to avoid dependency on the msg lifetime.
        let k = Scalar::from_hash(
            Sha512::default()
                .chain(&sig.R_bytes[..])
                .chain(&pk_bytes.0[..])
                .chain(msg),
        );

        self.signatures
            .entry(pk_bytes)
            // The common case is 1 signature per public key.
            // We could also consider using a smallvec here.
            .or_insert_with(|| Vec::with_capacity(1))
            .push((k, sig));
        self.batch_size += 1;
    }

    /// Perform batch verification, returning `Ok(())` if all signatures were
    /// valid and `Err` otherwise.
    ///
    /// # Warning
    ///
    /// Ed25519 has different verification rules for batched and non-batched
    /// verifications. This function does not have the same verification criteria
    /// as individual verification, which may reject some signatures this method
    /// accepts.
    #[allow(non_snake_case)]
    pub fn verify<R: RngCore + CryptoRng>(self, mut rng: R) -> Result<(), Error> {
        // The batch verification equation is
        //
        // [-sum(z_i * s_i)]B + sum([z_i]R_i) + sum([z_i * k_i]A_i) = 0.
        //
        // where for each signature i,
        // - A_i is the public key;
        // - R_i is the signature's R value;
        // - s_i is the signature's s value;
        // - k_i is the hash of the message and other data;
        // - z_i is a random 128-bit Scalar.
        //
        // Normally n signatures would require a multiscalar multiplication of
        // size 2*n + 1, together with 2*n point decompressions (to obtain A_i
        // and R_i). However, because we store batch entries in a HashMap
        // indexed by the public key, we can "coalesce" all z_i * k_i terms for
        // each distinct public key into a single coefficient.
        //
        // For n signatures from m public keys, this approach instead requires a
        // multiscalar multiplication of size n + m + 1 together with n + m
        // point decompressions. When m = n, so all signatures are from distinct
        // public keys, this is as efficient as the usual method. However, when
        // m = 1 and all signatures are from a single public key, this is nearly
        // twice as fast.

        let m = self.signatures.keys().count();

        let mut A_coeffs = Vec::with_capacity(m);
        let mut As = Vec::with_capacity(m);
        let mut R_coeffs = Vec::with_capacity(self.batch_size);
        let mut Rs = Vec::with_capacity(self.batch_size);
        let mut B_coeff = Scalar::zero();

        for (pk_bytes, sigs) in self.signatures.iter() {
            let A = CompressedEdwardsY(pk_bytes.0)
                .decompress()
                .ok_or(Error::InvalidSignature)?;

            let mut A_coeff = Scalar::zero();

            for (k, sig) in sigs.iter() {
                let R = CompressedEdwardsY(sig.R_bytes)
                    .decompress()
                    .ok_or(Error::InvalidSignature)?;
                let s = Scalar::from_canonical_bytes(sig.s_bytes).ok_or(Error::InvalidSignature)?;
                let z = Scalar::from(gen_u128(&mut rng));
                B_coeff -= z * s;
                Rs.push(R);
                R_coeffs.push(z);
                A_coeff += z * k;
            }

            As.push(A);
            A_coeffs.push(A_coeff);
        }

        use curve25519_dalek::constants::ED25519_BASEPOINT_POINT as B;
        use std::iter::once;
        let check = EdwardsPoint::vartime_multiscalar_mul(
            once(&B_coeff).chain(A_coeffs.iter()).chain(R_coeffs.iter()),
            once(&B).chain(As.iter()).chain(Rs.iter()),
        );

        if check.is_identity() {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }
}
