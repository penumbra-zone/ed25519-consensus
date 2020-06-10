use std::convert::TryFrom;

use curve25519_dalek::{
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
};
use sha2::{Digest, Sha512};

use crate::{Error, Signature};

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
    /// specification. However, it is not clear that the protocol specification
    /// matches the implementation in `libsodium` `1.0.15` used by `zcashd`. Note
    /// that the precise version is important because `libsodium` changed validation
    /// rules in point releases.
    ///
    /// Ed25519 permits implementations to choose whether or not to multiply by the
    /// cofactor in the verification check. The Zcash spec does not say whether
    /// cofactor multiplication is performed, but the verification function used by
    /// `zcashd` does not perform cofactor multiplication, so this implementation
    /// does not either.
    ///
    /// The spec says that the signature's `R` value
    ///
    /// > MUST represent a point on the Ed25519 curve of order at least `l`
    ///
    /// but `libsodium` `1.0.15` does not seem to check this directly. Instead it
    /// recomputes the expected `R` value and then compares its encoding against the
    /// provided encoding of `R`. This implementation does the same check.
    ///
    /// `R` is recomputed as `R <- [s]B - [k]A`. This is of low order if and only if
    /// `s = 0` and `[k]A` is of low order. Assuming that `k`, computed as a hash
    /// output, is uncontrollable, `[k]A` is of low order if and only if `A` is of
    /// low order. However, as noted in the [`PublicKey`] docs, public key validation
    /// does not ensure that `A` is of order at least `l`, only that its encoding is
    /// nonzero.
    ///
    /// [ps]: https://zips.z.cash/protocol/protocol.pdf#concretejssig
    #[allow(non_snake_case)]
    pub fn verify(&self, signature: &Signature, msg: &[u8]) -> Result<(), Error> {
        // Zcash consensus rule: `s` MUST represent an integer less than the prime `l`.
        let s = Scalar::from_canonical_bytes(signature.s_bytes).ok_or(Error::InvalidSignature)?;

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
