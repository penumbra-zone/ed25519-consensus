use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use curve25519_dalek::{
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    traits::{IsIdentity, VartimeMultiscalarMul},
};
use rand::thread_rng;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};
use tokio::sync::watch::{channel, Receiver, Sender};
use tower_service::Service;

use crate::{batch::VerificationRequest, Error, PublicKeyBytes, Signature};

/// Performs batch verification.
pub struct BatchVerifier {
    tx: Sender<Result<(), Error>>,
    rx: Receiver<Result<(), Error>>,
    /// The number of signatures per batch.
    batch_size: usize,
    /// The number of signatures currently queued for verification.
    num_sigs: usize,
    /// Signature data queued for verification.
    signatures: HashMap<PublicKeyBytes, Vec<(Scalar, Signature)>>,
}

// Shim to generate a u128 without importing `rand`.
fn gen_u128<R: RngCore + CryptoRng>(mut rng: R) -> u128 {
    let mut bytes = [0u8; 16];
    rng.fill_bytes(&mut bytes[..]);
    u128::from_le_bytes(bytes)
}

impl BatchVerifier {
    /// Construct a new batch verifier, targeting `batch_size` batches.
    ///
    /// Incoming verification requests will be buffered until the batch size is
    /// reached or the service is dropped, at which point the service performs batch
    /// verification to flush pending requests.
    pub fn new(batch_size: usize) -> BatchVerifier {
        // broadcast::channel requires setting an initial default
        // value, so that there is always one value for a receiver.
        // We will skip this value, but set it to Err to fail closed.
        let (tx, mut rx) = channel(Err(Error::InvalidSignature));
        // Skip the default so that rx.recv() waits for the next broadcast.
        let _ = rx.recv();

        BatchVerifier {
            tx,
            rx,
            batch_size,
            num_sigs: 0,
            signatures: HashMap::default(),
        }
    }

    /// Finalize the batch verification, resolving all pending `Response` futures.
    ///
    /// XXX should this spawn a task?
    #[allow(non_snake_case)]
    fn flush(&mut self) {
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
            let A = match CompressedEdwardsY(pk_bytes.0).decompress() {
                Some(A) => A,
                None => {
                    let _ = self.tx.broadcast(Err(Error::InvalidSignature));
                    return;
                }
            };
            let mut A_coeff = Scalar::zero();

            for (k, sig) in sigs.iter() {
                let (R, s) = match (
                    CompressedEdwardsY(sig.R_bytes).decompress(),
                    Scalar::from_canonical_bytes(sig.s_bytes),
                ) {
                    (Some(R), Some(s)) => (R, s),
                    _ => {
                        let _ = self.tx.broadcast(Err(Error::InvalidSignature));
                        return;
                    }
                };
                let z = Scalar::from(gen_u128(thread_rng()));
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
            let _ = self.tx.broadcast(Ok(()));
        } else {
            let _ = self.tx.broadcast(Err(Error::InvalidSignature));
        }
    }
}

impl Service<VerificationRequest<'_>> for BatchVerifier {
    type Response = ();
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<(), Error>> + Send + 'static>>;

    fn poll_ready(&mut self, _cx: &mut Context) -> Poll<Result<(), Error>> {
        // Flush the batch if we have reached the target batch_size.
        // Checking num_sigs >= batch_size rather than == protects
        // against callers who violate the Service contract.
        if self.num_sigs >= self.batch_size {
            self.flush()
        }
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: VerificationRequest) -> Self::Future {
        let (pk_bytes, sig, msg) = req;

        // Compute k now to avoid dependency on the 'msg lifetime.
        let k = Scalar::from_hash(
            Sha512::default()
                .chain(&sig.R_bytes[..])
                .chain(&pk_bytes.0[..])
                .chain(msg),
        );

        self.signatures
            .entry(pk_bytes)
            .or_insert_with(|| Vec::new())
            .push((k, sig));
        self.num_sigs += 1;

        let mut rx2 = self.rx.clone();
        Box::pin(async move {
            // Fail closed by converting a channel error to a signature failure.
            rx2.recv().await.unwrap_or(Err(Error::InvalidSignature))
        })
    }
}

impl Drop for BatchVerifier {
    fn drop(&mut self) {
        self.flush();
    }
}
