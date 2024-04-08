use core::convert::TryFrom;
use core::fmt::Formatter;

use curve25519_dalek::{constants, scalar::Scalar};
use rand_core::{CryptoRng, RngCore};
use serde::de::{self, Visitor};
use serde::ser::SerializeTuple;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha512};

use crate::{Error, Signature, VerificationKey, VerificationKeyBytes};

/// An Ed25519 signing key.
///
/// This is also called an expanded secret key by other implementations.
#[derive(Clone)]
pub struct SigningKey {
    s: Scalar,
    prefix: [u8; 32],
    vk: VerificationKey,
}

impl SigningKey {
    /// Obtain the verification key associated with this signing key.
    pub fn verification_key(&self) -> VerificationKey {
        self.vk
    }
}

/// Serialize the SigningKey as the expanded secret key
impl Serialize for SigningKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_tuple(64)?;
        for s in self.s.as_bytes() {
            seq.serialize_element(s)?;
        }
        for p in &self.prefix {
            seq.serialize_element(p)?;
        }
        seq.end()
    }
}

/// Deserialize bytes to SigningKey
impl<'de> Deserialize<'de> for SigningKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TupleVisitor;

        impl<'de> Visitor<'de> for TupleVisitor {
            type Value = SigningKey;

            fn expecting(&self, formatter: &mut Formatter) -> core::fmt::Result {
                formatter.write_str("an Ed25519 seed key or expanded secret key")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let mut bytes = [0u8; 64];
                for i in 0..64 {
                    bytes[i] = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(i, &self))?;
                }
                Ok(bytes.into())
            }
        }

        deserializer.deserialize_tuple(64, TupleVisitor)
    }
}

impl core::fmt::Debug for SigningKey {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        fmt.debug_struct("SigningKey")
            .field("s", &self.s)
            .field("prefix", &hex::encode(&self.prefix))
            .field("vk", &self.vk)
            .finish()
    }
}

impl<'a> From<&'a SigningKey> for VerificationKey {
    fn from(sk: &'a SigningKey) -> VerificationKey {
        sk.vk
    }
}

impl<'a> From<&'a SigningKey> for VerificationKeyBytes {
    fn from(sk: &'a SigningKey) -> VerificationKeyBytes {
        sk.vk.into()
    }
}

impl TryFrom<&[u8]> for SigningKey {
    type Error = Error;
    fn try_from(slice: &[u8]) -> Result<SigningKey, Error> {
        let mut bytes = [0u8; 64];
        if slice.len() == 32 {
            let h = Sha512::digest(slice);
            bytes[..].copy_from_slice(h.as_slice());
        } else if slice.len() == 64 {
            bytes[..].copy_from_slice(slice);
        } else {
            return Err(Error::InvalidSliceLength);
        }
        Ok(bytes.into())
    }
}

impl From<[u8; 64]> for SigningKey {
    #[allow(non_snake_case)]
    fn from(h: [u8; 64]) -> SigningKey {
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

        SigningKey {
            s,
            prefix,
            vk: VerificationKey {
                minus_A: -A,
                A_bytes: VerificationKeyBytes(A.compress().to_bytes()),
            },
        }
    }
}

impl From<SigningKey> for [u8; 64] {
    fn from(value: SigningKey) -> Self {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(value.s.as_bytes());
        bytes[32..].copy_from_slice(value.prefix.as_slice());
        bytes
    }
}

impl From<[u8; 32]> for SigningKey {
    fn from(seed: [u8; 32]) -> SigningKey {
        // Expand the seed to a 64-byte array with SHA512.
        let h = Sha512::digest(&seed);
        let mut bytes = [0u8; 64];
        bytes[..].copy_from_slice(h.as_slice());

        bytes.into()
    }
}

impl zeroize::Zeroize for SigningKey {
    fn zeroize(&mut self) {
        self.s.zeroize()
    }
}

impl SigningKey {
    /// Generate a new signing key.
    pub fn new<R: RngCore + CryptoRng>(mut rng: R) -> SigningKey {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes[..]);
        bytes.into()
    }

    /// Create a signature on `msg` using this key.
    #[allow(non_snake_case)]
    pub fn sign(&self, msg: &[u8]) -> Signature {
        let r = Scalar::from_hash(Sha512::default().chain(&self.prefix[..]).chain(msg));

        let R_bytes = (&r * &constants::ED25519_BASEPOINT_TABLE)
            .compress()
            .to_bytes();

        let k = Scalar::from_hash(
            Sha512::default()
                .chain(&R_bytes[..])
                .chain(&self.vk.A_bytes.0[..])
                .chain(msg),
        );

        let s_bytes = (r + k * self.s).to_bytes();

        Signature { R_bytes, s_bytes }
    }
}
