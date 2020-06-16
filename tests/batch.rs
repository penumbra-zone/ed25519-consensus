use rand::thread_rng;

use ed25519_zebra::*;

#[test]
fn batch_verify() {
    let mut batch = BatchVerifier::new();
    for _ in 0..32 {
        let sk = SecretKey::new(thread_rng());
        let pk_bytes = PublicKeyBytes::from(&sk);
        let msg = b"BatchVerifyTest";
        let sig = sk.sign(&msg[..]);
        batch.queue(pk_bytes, sig, &msg[..]);
    }
    assert!(batch.verify(thread_rng()).is_ok());
}
