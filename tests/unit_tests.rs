use rand::thread_rng;

use ed25519_zebra::{PublicKey, PublicKeyBytes, SecretKey};

#[test]
fn asref_vs_into_bytes() {
    let sk = SecretKey::new(thread_rng());
    let pk = PublicKey::from(&sk);
    let pkb = PublicKeyBytes::from(&sk);

    let sk_array: [u8; 32] = sk.into();
    let pk_array: [u8; 32] = pk.into();
    let pkb_array: [u8; 32] = pkb.into();

    assert_eq!(&sk_array[..], sk.as_ref());
    assert_eq!(&pk_array[..], pk.as_ref());
    assert_eq!(&pkb_array[..], pkb.as_ref());
}

#[test]
fn sign_and_verify() {
    let sk = SecretKey::new(thread_rng());
    let pk = PublicKey::from(&sk);

    let msg = b"ed25519-zebra test message";

    let sig = sk.sign(&msg[..]);

    assert_eq!(pk.verify(&sig, &msg[..]), Ok(()))
}
