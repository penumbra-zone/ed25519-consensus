use std::convert::TryFrom;

use curve25519_dalek::{
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
};
use sha2::{Digest, Sha512};

use crate::{constants, Error, Signature};

/// A refinement type for `[u8; 32]` indicating that the bytes represent an
/// encoding of an Ed25519 public key.
///
/// This is useful for representing an encoded public key, while the
/// [`PublicKey`] type in this library caches other decoded state used in
/// signature verification.  
///
/// A `PublicKeyBytes` can be used to verify a single signature using the
/// following idiom:
/// ```
/// use std::convert::TryFrom;
/// # use rand::thread_rng;
/// # use ed25519_zebra::*;
/// # let msg = b"Zcash";
/// # let sk = SecretKey::new(thread_rng());
/// # let sig = sk.sign(msg);
/// # let pk_bytes: PublicKeyBytes = PublicKey::from(&sk).into();
/// PublicKey::try_from(pk_bytes)
///     .and_then(|pk| pk.verify(&sig, msg));
/// ```
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PublicKeyBytes(pub(crate) [u8; 32]);

impl core::fmt::Debug for PublicKeyBytes {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        fmt.debug_tuple("PublicKeyBytes")
            .field(&hex::encode(&self.0))
            .finish()
    }
}

impl AsRef<[u8]> for PublicKeyBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

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
/// ## Zcash-specific consensus properties
///
/// Ed25519 checks are described in [§5.4.5][ps] of the Zcash protocol
/// specification. However, it is not clear that the protocol specification
/// matches the implementation in `libsodium` `1.0.15` used by `zcashd`. Note
/// that the precise version is important because `libsodium` changed validation
/// rules in point releases.
///
/// The spec says that a public key `A` is
///
/// > a point of order `l` on the Ed25519 curve, in the encoding specified by…
///
/// but `libsodium` `1.0.15` does not check this. Instead it only checks whether
/// the encoding of `A` is an encoding of a point on the curve and that the
/// encoding is not all zeros. This implementation matches the `libsodium`
/// behavior.  This has implications for signature verification behaviour, as noted
/// in the [`PublicKey::verify`] documentation.
///
/// [ps]: https://zips.z.cash/protocol/protocol.pdf#concretejssig
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

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.A_bytes.0[..]
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
        // libsodium behavior: public key bytes must not be all 0
        // libsodium 1.0.15 crypto_sign/ed25519/ref10/open.c:138-143
        // Note: this is different from the description in the spec.
        if bytes.0 == [0; 32] {
            return Err(Error::MalformedPublicKey);
        }

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
    ///
    /// ## Zcash-specific consensus properties
    ///
    /// Ed25519 checks are described in [§5.4.5][ps] of the Zcash protocol
    /// specification. Ed25519 validation is not well-specified, and the original
    /// implementation of JoinSplit signatures for `zcashd` inherited its precise
    /// validation rules from a specific build configuration of `libsodium`
    /// `1.0.15`. Note that the precise version is important because `libsodium`
    /// changed validation rules in point releases.
    ///
    /// The additional validation checks are that:
    ///
    /// * `s` MUST represent an integer less than the prime `l`, per `libsodium`
    /// `1.0.15` `crypto_sign/ed25519/ref10/open.c:126`;
    ///
    /// * `R` MUST NOT be one of the excluded encodings, per `libsodium` `1.0.15`
    /// `crypto_sign/ed25519/ref10/open.c:127`;
    ///
    /// * The public key bytes must not be all 0, per `libsodium` `1.0.15`
    /// `crypto_sign/ed25519/ref10/open.c:138-143`, which we maintain as an
    /// invariant on the `PublicKey` type.
    ///
    /// [ps]: https://zips.z.cash/protocol/protocol.pdf#concretejssig
    #[allow(non_snake_case)]
    pub fn verify(&self, signature: &Signature, msg: &[u8]) -> Result<(), Error> {
        // Zcash consensus rule: `s` MUST represent an integer less than the prime `l`.
        // libsodium 1.0.15 crypto_sign/ed25519/ref10/open.c:126
        let s = Scalar::from_canonical_bytes(signature.s_bytes).ok_or(Error::InvalidSignature)?;

        // Zcash consensus rule: `R` MUST NOT be one of the encodings excluded by libsodium 1.0.15
        // libsodium 1.0.15 crypto_sign/ed25519/ref10/open.c:127
        for excluded in &constants::EXCLUDED_POINT_ENCODINGS {
            if &signature.R_bytes == excluded {
                return Err(Error::InvalidSignature);
            }
        }

        // libsodium behavior: public key bytes must not be all 0
        // libsodium 1.0.15 crypto_sign/ed25519/ref10/open.c:138-143
        // Note: this is different from the description in the spec.
        // No-op, since we maintain this invariant in the PublicKey type.

        let k = Scalar::from_hash(
            Sha512::default()
                .chain(&signature.R_bytes[..])
                .chain(&self.A_bytes.0[..])
                .chain(msg),
        );

        // We expect to recompute R as [s]B - [k]A = [k](-A) + [s]B.
        let R = EdwardsPoint::vartime_double_scalar_mul_basepoint(&k, &self.minus_A, &s);

        if R.compress().to_bytes() == signature.R_bytes {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }
}
