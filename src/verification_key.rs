use std::convert::{TryFrom, TryInto};

use curve25519_dalek::{
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
};
use sha2::{Digest, Sha512};

use crate::{constants, Error, Signature};

/// A refinement type for `[u8; 32]` indicating that the bytes represent an
/// encoding of an Ed25519 verification key.
///
/// This is useful for representing an encoded verification key, while the
/// [`VerificationKey`] type in this library caches other decoded state used in
/// signature verification.  
///
/// A `VerificationKeyBytes` can be used to verify a single signature using the
/// following idiom:
/// ```
/// use std::convert::TryFrom;
/// # use rand::thread_rng;
/// # use ed25519_zebra::*;
/// # let msg = b"Zcash";
/// # let sk = SigningKey::new(thread_rng());
/// # let sig = sk.sign(msg);
/// # let vk_bytes = VerificationKeyBytes::from(&sk);
/// VerificationKey::try_from(vk_bytes)
///     .and_then(|vk| vk.verify(&sig, msg));
/// ```
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VerificationKeyBytes(pub(crate) [u8; 32]);

impl core::fmt::Debug for VerificationKeyBytes {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        fmt.debug_tuple("VerificationKeyBytes")
            .field(&hex::encode(&self.0))
            .finish()
    }
}

impl AsRef<[u8]> for VerificationKeyBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl TryFrom<&[u8]> for VerificationKeyBytes {
    type Error = Error;
    fn try_from(slice: &[u8]) -> Result<VerificationKeyBytes, Error> {
        if slice.len() == 32 {
            let mut bytes = [0u8; 32];
            bytes[..].copy_from_slice(slice);
            Ok(bytes.into())
        } else {
            Err(Error::InvalidSliceLength)
        }
    }
}

impl From<[u8; 32]> for VerificationKeyBytes {
    fn from(bytes: [u8; 32]) -> VerificationKeyBytes {
        VerificationKeyBytes(bytes)
    }
}

impl From<VerificationKeyBytes> for [u8; 32] {
    fn from(refined: VerificationKeyBytes) -> [u8; 32] {
        refined.0
    }
}

/// A valid Ed25519 verification key.
///
/// This is also called a public key by other implementations.
///
/// This type holds decompressed state used in signature verification; if the
/// verification key may not be used immediately, it is probably better to use
/// [`VerificationKeyBytes`], which is a refinement type for `[u8; 32]`.
///
/// ## Zcash-specific consensus properties
///
/// Ed25519 checks are described in [§5.4.5][ps] of the Zcash protocol
/// specification. However, it is not clear that the protocol specification
/// matches the implementation in `libsodium` `1.0.15` used by `zcashd`. Note
/// that the precise version is important because `libsodium` changed validation
/// rules in point releases.
///
/// The spec says that a verification key `A` is
///
/// > a point of order `l` on the Ed25519 curve, in the encoding specified by…
///
/// but `libsodium` `1.0.15` does not check this. Instead it only checks whether
/// the encoding of `A` is an encoding of a point on the curve and that the
/// encoding is not all zeros. This implementation matches the `libsodium`
/// behavior.  This has implications for signature verification behaviour, as noted
/// in the [`VerificationKey::verify`] documentation.
///
/// [ps]: https://zips.z.cash/protocol/protocol.pdf#concretejssig
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "VerificationKeyBytes"))]
#[cfg_attr(feature = "serde", serde(into = "VerificationKeyBytes"))]
#[allow(non_snake_case)]
pub struct VerificationKey {
    pub(crate) A_bytes: VerificationKeyBytes,
    pub(crate) minus_A: EdwardsPoint,
}

impl From<VerificationKey> for VerificationKeyBytes {
    fn from(vk: VerificationKey) -> VerificationKeyBytes {
        vk.A_bytes
    }
}

impl AsRef<[u8]> for VerificationKey {
    fn as_ref(&self) -> &[u8] {
        &self.A_bytes.0[..]
    }
}

impl From<VerificationKey> for [u8; 32] {
    fn from(vk: VerificationKey) -> [u8; 32] {
        vk.A_bytes.0
    }
}

impl TryFrom<VerificationKeyBytes> for VerificationKey {
    type Error = Error;
    #[allow(non_snake_case)]
    fn try_from(bytes: VerificationKeyBytes) -> Result<Self, Self::Error> {
        // libsodium behavior: public key bytes must not be all 0
        // libsodium 1.0.15 crypto_sign/ed25519/ref10/open.c:138-143
        // Note: this is different from the description in the spec.
        if bytes.0 == [0; 32] {
            return Err(Error::MalformedPublicKey);
        }

        let A = CompressedEdwardsY(bytes.0)
            .decompress()
            .ok_or(Error::MalformedPublicKey)?;

        Ok(VerificationKey {
            A_bytes: bytes,
            minus_A: -A,
        })
    }
}

impl TryFrom<&[u8]> for VerificationKey {
    type Error = Error;
    fn try_from(slice: &[u8]) -> Result<VerificationKey, Error> {
        VerificationKeyBytes::try_from(slice).and_then(|vkb| vkb.try_into())
    }
}

impl TryFrom<[u8; 32]> for VerificationKey {
    type Error = Error;
    fn try_from(bytes: [u8; 32]) -> Result<Self, Self::Error> {
        VerificationKeyBytes::from(bytes).try_into()
    }
}

impl VerificationKey {
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
    /// invariant on the `VerificationKey` type.
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
