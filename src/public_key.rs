use std::convert::TryFrom;

use curve25519_dalek::{
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
};
use sha2::{Digest, Sha512};

use crate::{Error, Signature};

/// A refinement type for `[u8; 32]` indicating that the bytes represent
/// an encoding of an Ed25519 public key.
///
/// This is useful for representing a compressed public key; the
/// [`PublicKey`] type in this library holds other decompressed state
/// used in signature verification.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PublicKeyBytes(pub(crate) [u8; 32]);

impl From<[u8; 32]> for PublicKeyBytes {
    fn from(bytes: [u8; 32]) -> PublicKeyBytes {
        PublicKeyBytes(bytes)
    }
}

impl From<PublicKeyBytes> for [u8; 32] {
    fn from(refined: PublicKeyBytes) -> [u8; 32] {
        refined.0
    }
}

/// A valid Ed25519 public key.
///
/// This type holds decompressed state used in signature verification; if the
/// public key may not be used immediately, it is probably better to use
/// [`PublicKeyBytes`], which is a refinement type for `[u8; 32]`.
///
/// ## Consensus properties
///
/// Valid Ed25519 public keys are defined in
/// [§5.4.5](https://zips.z.cash/protocol/protocol.pdf#concretejssig) of the
/// Zcash protocol specification.
///
/// FIXME: the spec says that a public key must be a point of order `l`; is
/// this exactly what is meant?  Would a public key of order `8*l` be rejected
/// by the implementation?  Or is this intended to specify that the point must
/// not be of *small* order?
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "PublicKeyBytes"))]
#[cfg_attr(feature = "serde", serde(into = "PublicKeyBytes"))]
#[allow(non_snake_case)]
pub struct PublicKey {
    pub(crate) A_bytes: PublicKeyBytes,
    pub(crate) minus_A: EdwardsPoint,
}

impl From<PublicKey> for PublicKeyBytes {
    fn from(pk: PublicKey) -> PublicKeyBytes {
        pk.A_bytes
    }
}

impl From<PublicKey> for [u8; 32] {
    fn from(pk: PublicKey) -> [u8; 32] {
        pk.A_bytes.0
    }
}

impl TryFrom<PublicKeyBytes> for PublicKey {
    type Error = Error;
    #[allow(non_snake_case)]
    fn try_from(bytes: PublicKeyBytes) -> Result<Self, Self::Error> {
        // XXX check consensus rules, see FIXME above
        let A = CompressedEdwardsY(bytes.0)
            .decompress()
            .ok_or(Error::MalformedPublicKey)?;

        Ok(PublicKey {
            A_bytes: bytes,
            minus_A: -A,
        })
    }
}

impl TryFrom<[u8; 32]> for PublicKey {
    type Error = Error;
    fn try_from(bytes: [u8; 32]) -> Result<Self, Self::Error> {
        use std::convert::TryInto;
        PublicKeyBytes::from(bytes).try_into()
    }
}

impl PublicKey {
    /// Verify a purported `signature` on the given `msg`.
    #[allow(non_snake_case)]
    pub fn verify(&self, signature: &Signature, msg: &[u8]) -> Result<(), Error> {
        // Zcash consensus rule: S MUST represent an integer less than the prime `l`
        let s = Scalar::from_canonical_bytes(signature.s_bytes).ok_or(Error::InvalidSignature)?;

        // Zcash consensus rule: R MUST represent a point
        //     a. on the Ed25519 curve
        //     b. of order at least `l`
        let R = CompressedEdwardsY(signature.R_bytes)
            .decompress()
            .ok_or(Error::InvalidSignature)
            .and_then(|R| {
                if R.is_small_order() {
                    Err(Error::InvalidSignature)
                } else {
                    Ok(R)
                }
            })?;

        let k = Scalar::from_hash(
            Sha512::default()
                .chain(&signature.R_bytes[..])
                .chain(&self.A_bytes.0[..])
                .chain(msg),
        );

        // We expect to recompute R as [s]B - [k]A = [k](-A) + [s]B.
        let recomputed_R = EdwardsPoint::vartime_double_scalar_mul_basepoint(&k, &self.minus_A, &s);

        // XXX the Zcash spec does not seem to explicitly specify whether
        // the Ed25519 verification check includes a cofactor multiplication (?)

        // Check whether [8]R = [8]([s]B - [k]A), i.e., whether R - ([s]B - [k]A) is of small order.
        if (R - recomputed_R).is_small_order() {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }
}
