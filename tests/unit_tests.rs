use rand::thread_rng;

use ed25519_zebra::{PublicKey, SecretKey};

#[test]
fn sign_and_verify() {
    let sk = SecretKey::new(thread_rng());
    let pk = PublicKey::from(&sk);

    let msg = b"ed25519-zebra test message";

    let sig = sk.sign(&msg[..]);

    assert_eq!(pk.verify(&sig, &msg[..]), Ok(()))
}
