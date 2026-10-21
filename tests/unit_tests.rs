use std::convert::TryFrom;

use rand::thread_rng;

use ed25519_consensus::{Signature, SigningKey, VerificationKey, VerificationKeyBytes};

#[test]
fn parsing() {
    let sk = SigningKey::new(thread_rng());
    let pk = VerificationKey::from(&sk);
    let pkb = VerificationKeyBytes::from(&sk);
    let sig = sk.sign(b"test");

    // Most of these types don't implement Eq, so we check a round trip
    // conversion to bytes, using these as the reference points:

    let sk_array: [u8; 32] = sk.clone().into();
    let pk_array: [u8; 32] = pk.into();
    let pkb_array: [u8; 32] = pkb.into();
    let sig_array: [u8; 64] = sig.into();

    let sk2 = SigningKey::try_from(sk.as_ref()).unwrap();
    let pk2 = VerificationKey::try_from(pk.as_ref()).unwrap();
    let pkb2 = VerificationKeyBytes::try_from(pkb.as_ref()).unwrap();
    let sig2 = Signature::try_from(<[u8; 64]>::from(sig).as_ref()).unwrap();

    assert_eq!(&sk_array[..], sk2.as_ref());
    assert_eq!(&pk_array[..], pk2.as_ref());
    assert_eq!(&pkb_array[..], pkb2.as_ref());
    assert_eq!(&sig_array[..], <[u8; 64]>::from(sig2).as_ref());

    let sk3: SigningKey = bincode::deserialize(sk.as_ref()).unwrap();
    let pk3: VerificationKey = bincode::deserialize(pk.as_ref()).unwrap();
    let pkb3: VerificationKeyBytes = bincode::deserialize(pkb.as_ref()).unwrap();
    let sig3: Signature = bincode::deserialize(<[u8; 64]>::from(sig).as_ref()).unwrap();

    assert_eq!(&sk_array[..], sk3.as_ref());
    assert_eq!(&pk_array[..], pk3.as_ref());
    assert_eq!(&pkb_array[..], pkb3.as_ref());
    assert_eq!(&sig_array[..], <[u8; 64]>::from(sig3).as_ref());
}

#[test]
fn sign_and_verify() {
    let sk = SigningKey::new(thread_rng());
    let pk = VerificationKey::from(&sk);

    let msg = b"ed25519-consensus test message";

    let sig = sk.sign(&msg[..]);

    assert_eq!(pk.verify(&sig, &msg[..]), Ok(()))
}

#[test]
fn zeroize_clears_secret_material() {
    use zeroize::Zeroize;

    let mut sk1 = SigningKey::new(thread_rng());
    let mut sk2 = SigningKey::new(thread_rng());
    sk1.zeroize();
    sk2.zeroize();

    // With the scalar and the nonce prefix both zeroed, a signature depends only on the
    // message, so two distinct zeroized keys must produce the same signature.
    let msg = b"ed25519-consensus zeroize test message";
    assert_eq!(
        <[u8; 64]>::from(sk1.sign(msg)),
        <[u8; 64]>::from(sk2.sign(msg))
    );
    assert_eq!(sk1.as_bytes(), &[0u8; 32]);
}

#[test]
fn signing_key_is_zeroize_on_drop() {
    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<SigningKey>();
}

#[test]
fn debug_does_not_render_secrets() {
    use sha2::{Digest, Sha512};

    let seed = [7u8; 32];
    let sk = SigningKey::from(seed);
    let expanded = Sha512::digest(&seed[..]);
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&expanded[..32]);
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;

    for output in [format!("{:?}", sk), format!("{:#?}", sk)] {
        for secret in [&seed[..], &scalar[..], &expanded[32..]] {
            assert!(!output.contains(&hex::encode(secret)), "{}", output);
            assert!(!output.contains(&format!("{:?}", secret)), "{}", output);
        }
    }
}
