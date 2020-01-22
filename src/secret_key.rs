use rand_core::{CryptoRng, RngCore};

use crate::{PublicKey, Signature};

/// An Ed25519 secret key.
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(from = "SerdeHelper"))]
#[cfg_attr(feature = "serde", serde(into = "SerdeHelper"))]
pub struct SecretKey {
    // XXX add fields
    pk: PublicKey,
}

impl<'a> From<&'a SecretKey> for PublicKey {
    fn from(sk: &'a SecretKey) -> PublicKey {
        sk.pk.clone()
    }
}

impl From<SecretKey> for [u8; 32] {
    fn from(_sk: SecretKey) -> [u8; 32] {
        unimplemented!();
    }
}

impl From<[u8; 32]> for SecretKey {
    fn from(_bytes: [u8; 32]) -> SecretKey {
        unimplemented!();
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
    pub fn new<R: RngCore + CryptoRng>(mut _rng: R) -> SecretKey {
        unimplemented!();
    }

    /// Create a signature on `msg` using this `SecretKey`.
    pub fn sign(&self, _msg: &[u8]) -> Signature {
        unimplemented!();
    }
}
