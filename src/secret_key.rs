use curve25519_dalek::{constants, scalar::Scalar};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};

use crate::{PublicKey, PublicKeyBytes, Signature};

/// An Ed25519 secret key.
#[derive(Copy, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(from = "SerdeHelper"))]
#[cfg_attr(feature = "serde", serde(into = "SerdeHelper"))]
pub struct SecretKey {
    seed: [u8; 32],
    s: Scalar,
    prefix: [u8; 32],
    pk: PublicKey,
}

impl core::fmt::Debug for SecretKey {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        fmt.debug_struct("SecretKey")
            .field("seed", &hex::encode(&self.seed))
            .field("s", &self.s)
            .field("prefix", &hex::encode(&self.prefix))
            .field("pk", &self.pk)
            .finish()
    }
}

impl<'a> From<&'a SecretKey> for PublicKey {
    fn from(sk: &'a SecretKey) -> PublicKey {
        sk.pk
    }
}

impl<'a> From<&'a SecretKey> for PublicKeyBytes {
    fn from(sk: &'a SecretKey) -> PublicKeyBytes {
        sk.pk.into()
    }
}

impl AsRef<[u8]> for SecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.seed[..]
    }
}

impl From<SecretKey> for [u8; 32] {
    fn from(sk: SecretKey) -> [u8; 32] {
        sk.seed
    }
}

impl From<[u8; 32]> for SecretKey {
    #[allow(non_snake_case)]
    fn from(seed: [u8; 32]) -> SecretKey {
        // Expand the seed to a 64-byte array with SHA512.
        let h = Sha512::digest(&seed[..]);

        // Convert the low half to a scalar with Ed25519 "clamping"
        let s = {
            let mut scalar_bytes = [0u8; 32];
            scalar_bytes[..].copy_from_slice(&h.as_slice()[0..32]);
            scalar_bytes[0] &= 248;
            scalar_bytes[31] &= 127;
            scalar_bytes[31] |= 64;
            Scalar::from_bits(scalar_bytes)
        };

        // Extract and cache the high half.
        let prefix = {
            let mut prefix = [0u8; 32];
            prefix[..].copy_from_slice(&h.as_slice()[32..64]);
            prefix
        };

        // Compute the public key as A = [s]B.
        let A = &s * &constants::ED25519_BASEPOINT_TABLE;

        SecretKey {
            seed,
            s,
            prefix,
            pk: PublicKey {
                minus_A: -A,
                A_bytes: PublicKeyBytes(A.compress().to_bytes()),
            },
        }
    }
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
struct SerdeHelper([u8; 32]);

impl From<SerdeHelper> for SecretKey {
    fn from(helper: SerdeHelper) -> SecretKey {
        helper.0.into()
    }
}

impl From<SecretKey> for SerdeHelper {
    fn from(sk: SecretKey) -> Self {
        Self(sk.into())
    }
}

impl SecretKey {
    /// Generate a new secret key.
    pub fn new<R: RngCore + CryptoRng>(mut rng: R) -> SecretKey {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes[..]);
        bytes.into()
    }

    /// Create a signature on `msg` using this `SecretKey`.
    #[allow(non_snake_case)]
    pub fn sign(&self, msg: &[u8]) -> Signature {
        let r = Scalar::from_hash(Sha512::default().chain(&self.prefix[..]).chain(msg));

        let R_bytes = (&r * &constants::ED25519_BASEPOINT_TABLE)
            .compress()
            .to_bytes();

        let k = Scalar::from_hash(
            Sha512::default()
                .chain(&R_bytes[..])
                .chain(&self.pk.A_bytes.0[..])
                .chain(msg),
        );

        let s_bytes = (r + k * self.s).to_bytes();

        Signature { R_bytes, s_bytes }
    }
}
