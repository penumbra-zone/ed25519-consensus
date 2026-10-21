use core::convert::TryFrom;

use curve25519_dalek::{constants, scalar::Scalar};
use rand_core::{CryptoRng, RngCore};
use sha2::{digest::FixedOutputDirty, Digest, Sha512};
use zeroize::{Zeroize, Zeroizing};

use crate::{Error, Signature, VerificationKey, VerificationKeyBytes};

/// An Ed25519 signing key.
///
/// This is also called a secret key by other implementations.
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(from = "SerdeHelper"))]
#[cfg_attr(feature = "serde", serde(into = "SerdeHelper"))]
pub struct SigningKey {
    seed: [u8; 32],
    s: Scalar,
    prefix: [u8; 32],
    vk: VerificationKey,
}

impl SigningKey {
    /// Returns the byte encoding of the signing key.
    ///
    /// This is the same as `.into()`, but does not require type inference.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.seed
    }

    /// View the byte encoding of the signing key.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.seed
    }

    /// Obtain the verification key associated with this signing key.
    pub fn verification_key(&self) -> VerificationKey {
        self.vk
    }
}

impl core::fmt::Debug for SigningKey {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        fmt.debug_struct("SigningKey")
            .field("vk", &self.vk)
            .finish_non_exhaustive()
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

impl AsRef<[u8]> for SigningKey {
    fn as_ref(&self) -> &[u8] {
        &self.seed[..]
    }
}

impl From<SigningKey> for [u8; 32] {
    fn from(sk: SigningKey) -> [u8; 32] {
        sk.seed
    }
}

impl TryFrom<&[u8]> for SigningKey {
    type Error = Error;
    fn try_from(slice: &[u8]) -> Result<SigningKey, Error> {
        let seed = <&[u8; 32]>::try_from(slice).map_err(|_| Error::InvalidSliceLength)?;
        Ok(SigningKey::from_seed(seed))
    }
}

impl From<[u8; 32]> for SigningKey {
    fn from(mut seed: [u8; 32]) -> SigningKey {
        let sk = SigningKey::from_seed(&seed);
        seed.zeroize();
        sk
    }
}

impl SigningKey {
    #[allow(non_snake_case)]
    fn from_seed(seed: &[u8; 32]) -> SigningKey {
        // Expand the seed to a 64-byte array with SHA512.
        let h = sha512_wiped(&[&seed[..]]);

        // Convert the low half to a scalar with Ed25519 "clamping"
        let s = {
            let mut scalar_bytes = Zeroizing::new([0u8; 32]);
            scalar_bytes.copy_from_slice(&h[0..32]);
            scalar_bytes[0] &= 248;
            scalar_bytes[31] &= 127;
            scalar_bytes[31] |= 64;
            Zeroizing::new(Scalar::from_bits(*scalar_bytes))
        };

        // Compute the public key as A = [s]B.
        let A = &*s * &constants::ED25519_BASEPOINT_TABLE;

        let mut sk = SigningKey {
            seed: *seed,
            s: *s,
            prefix: [0u8; 32],
            vk: VerificationKey {
                minus_A: -A,
                A_bytes: VerificationKeyBytes(A.compress().to_bytes()),
            },
        };
        // Cache the high half.
        sk.prefix.copy_from_slice(&h[32..64]);
        sk
    }
}

/// SHA-512 of the concatenated `parts`, computed in a hasher state that is wiped on drop and
/// returned in a buffer that is wiped on drop.
fn sha512_wiped(parts: &[&[u8]]) -> Zeroizing<[u8; 64]> {
    let mut hasher = WipingSha512::default();
    for part in parts {
        hasher.0.update(part);
    }
    let mut out = Zeroizing::new([0u8; 64]);
    hasher.0.finalize_into_dirty((&mut out[..]).into());
    out
}

/// A SHA-512 state, which holds its buffered input and chaining value, wiped on drop.
#[derive(Default)]
struct WipingSha512(Sha512);

impl Drop for WipingSha512 {
    fn drop(&mut self) {
        // SAFETY: `Sha512` holds only integers and byte arrays, has no drop glue and owns no
        // outside data, so all-zero bytes are a valid value; nothing reads it afterwards.
        unsafe { zeroize::zeroize_flat_type(&mut self.0 as *mut Sha512) }
    }
}

impl zeroize::ZeroizeOnDrop for WipingSha512 {}

impl zeroize::Zeroize for SigningKey {
    fn zeroize(&mut self) {
        self.seed.zeroize();
        self.s.zeroize();
        self.prefix.zeroize()
    }
}

impl Drop for SigningKey {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(self)
    }
}

impl zeroize::ZeroizeOnDrop for SigningKey {}

#[cfg_attr(feature = "serde", derive(serde::Serialize))]
struct SerdeHelper([u8; 32]);

impl Drop for SerdeHelper {
    fn drop(&mut self) {
        self.0.zeroize()
    }
}

impl zeroize::ZeroizeOnDrop for SerdeHelper {}

/// Reads the encoding a derived `Deserialize` reads, a newtype around a 32-tuple of bytes, and
/// writes each byte straight into the `SerdeHelper` that wipes it.
#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for SerdeHelper {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_newtype_struct("SerdeHelper", SerdeHelperVisitor)
    }
}

#[cfg(feature = "serde")]
struct SerdeHelperVisitor;

#[cfg(feature = "serde")]
impl<'de> serde::de::Visitor<'de> for SerdeHelperVisitor {
    type Value = SerdeHelper;

    fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str("tuple struct SerdeHelper")
    }

    fn visit_newtype_struct<D: serde::Deserializer<'de>>(
        self,
        d: D,
    ) -> Result<SerdeHelper, D::Error> {
        serde::de::DeserializeSeed::deserialize(SeedVisitor, d)
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<SerdeHelper, A::Error> {
        seq.next_element_seed(SeedVisitor)?
            .ok_or_else(|| serde::de::Error::invalid_length(0, &self))
    }
}

#[cfg(feature = "serde")]
#[derive(Clone, Copy)]
struct SeedVisitor;

#[cfg(feature = "serde")]
impl<'de> serde::de::DeserializeSeed<'de> for SeedVisitor {
    type Value = SerdeHelper;

    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<SerdeHelper, D::Error> {
        d.deserialize_tuple(32, self)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::de::Visitor<'de> for SeedVisitor {
    type Value = SerdeHelper;

    fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str("an array of length 32")
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<SerdeHelper, A::Error> {
        let mut helper = SerdeHelper([0u8; 32]);
        for (i, byte) in helper.0.iter_mut().enumerate() {
            *byte = seq
                .next_element()?
                .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
        }
        Ok(helper)
    }
}

impl From<SerdeHelper> for SigningKey {
    fn from(helper: SerdeHelper) -> SigningKey {
        SigningKey::from_seed(&helper.0)
    }
}

impl From<SigningKey> for SerdeHelper {
    fn from(sk: SigningKey) -> Self {
        Self(sk.seed)
    }
}

impl SigningKey {
    /// Generate a new signing key.
    pub fn new<R: RngCore + CryptoRng>(mut rng: R) -> SigningKey {
        let mut bytes = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(&mut bytes[..]);
        SigningKey::from_seed(&bytes)
    }

    /// Create a signature on `msg` using this key.
    #[allow(non_snake_case)]
    pub fn sign(&self, msg: &[u8]) -> Signature {
        let r = Zeroizing::new(Scalar::from_bytes_mod_order_wide(&sha512_wiped(&[
            &self.prefix[..],
            msg,
        ])));

        let R_bytes = (&*r * &constants::ED25519_BASEPOINT_TABLE)
            .compress()
            .to_bytes();

        let k = Scalar::from_hash(
            Sha512::default()
                .chain(&R_bytes[..])
                .chain(&self.vk.A_bytes.0[..])
                .chain(msg),
        );

        let ks = Zeroizing::new(k * self.s);
        let s_bytes = (*r + *ks).to_bytes();

        Signature { R_bytes, s_bytes }
    }
}

#[cfg(test)]
mod tests {
    use core::mem::{size_of, MaybeUninit};

    use super::*;

    fn secret() -> [u8; 32] {
        let mut secret = [0u8; 32];
        for (i, b) in secret.iter_mut().enumerate() {
            *b = 0x80 | i as u8;
        }
        secret
    }

    fn reversed(secret: &[u8; 32]) -> [u8; 32] {
        let mut reversed = *secret;
        reversed.reverse();
        reversed
    }

    /// Whether `secret`, in either byte order, is in `value`'s storage before and after dropping
    /// it in place.
    fn residue<T>(value: T, secret: &[u8; 32]) -> (bool, bool) {
        let mut slot = MaybeUninit::<T>::zeroed();
        slot.write(value);
        let needles = [*secret, reversed(secret)];
        let holds = |slot: &MaybeUninit<T>| {
            let base = slot.as_ptr().cast::<u8>();
            needles.iter().any(|needle| {
                (0..=size_of::<T>() - needle.len()).any(|start| {
                    needle
                        .iter()
                        .enumerate()
                        // SAFETY: every offset is inside `slot`.
                        .all(|(i, b)| unsafe { base.add(start + i).read_volatile() } == *b)
                })
            })
        };
        let before = holds(&slot);
        // SAFETY: `write` initialised the slot, and it is never read as a `T` afterwards.
        unsafe { slot.assume_init_drop() };
        (before, holds(&slot))
    }

    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}

    #[test]
    fn test_secret_helpers_are_zeroize_on_drop() {
        assert_zeroize_on_drop::<SigningKey>();
        assert_zeroize_on_drop::<WipingSha512>();
        assert_zeroize_on_drop::<SerdeHelper>();
    }

    #[test]
    fn test_residue_detects_unwiped_secret() {
        let secret = secret();
        assert_eq!(residue(secret, &secret), (true, true));
        assert_eq!(residue(reversed(&secret), &secret), (true, true));
    }

    /// Whether `output` renders `secret`, in either byte order, as lower- or upper-case hex or as
    /// a decimal byte list, whitespace ignored.
    #[cfg(feature = "std")]
    fn renders(output: &str, secret: &[u8; 32]) -> bool {
        let output: String = output.chars().filter(|c| !c.is_whitespace()).collect();
        [*secret, reversed(secret)].iter().any(|needle| {
            let list = needle
                .iter()
                .map(|b| b.to_string())
                .collect::<Vec<_>>()
                .join(",");
            [hex::encode(needle), hex::encode_upper(needle), list]
                .iter()
                .any(|rendering| output.contains(rendering.as_str()))
        })
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_signing_key_debug_renders_no_secret() {
        let sk = SigningKey::from(secret());
        let secrets = [sk.seed, sk.s.to_bytes(), sk.prefix];
        for output in [format!("{:?}", sk), format!("{:#?}", sk)] {
            for secret in &secrets {
                assert!(!renders(&output, secret), "{}", output);
            }
        }
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_renders_detects_rendered_secret() {
        let secret = secret();
        let backwards = reversed(&secret);
        for output in [
            format!("seed: {}", hex::encode(secret)),
            format!("seed: {}", hex::encode_upper(backwards)),
            format!("{:?}", secret),
            format!("{:#?}", backwards),
        ] {
            assert!(renders(&output, &secret), "{}", output);
        }
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_serde_helper_reads_its_serialized_form() {
        let secret = secret();
        let bytes = bincode::serialize(&SerdeHelper(secret)).unwrap();
        assert_eq!(bytes, secret);
        assert_eq!(
            bincode::deserialize::<SerdeHelper>(&bytes).unwrap().0,
            secret
        );
        assert!(bincode::deserialize::<SerdeHelper>(&bytes[..31]).is_err());
    }

    #[test]
    fn test_sha512_state_wiped_on_drop() {
        let secret = secret();
        let mut hasher = WipingSha512::default();
        hasher.0.update(&secret[..]);
        let mut out = [0u8; 64];
        hasher.0.finalize_into_dirty((&mut out[..]).into());
        assert_eq!(residue(hasher, &secret), (true, false));
    }

    #[test]
    fn test_serde_helper_wiped_on_drop() {
        let secret = secret();
        assert_eq!(residue(SerdeHelper(secret), &secret), (true, false));
    }

    #[test]
    fn test_sha512_wiped_matches_sha512() {
        let secret = secret();
        let expected = Sha512::default()
            .chain(&secret[..])
            .chain(b"msg")
            .finalize();
        assert_eq!(&sha512_wiped(&[&secret[..], b"msg"])[..], &expected[..]);
    }
}
