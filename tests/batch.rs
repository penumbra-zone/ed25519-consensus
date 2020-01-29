use futures::stream::{FuturesUnordered, Stream, StreamExt};
use rand::thread_rng;
use tokio::runtime::Runtime;
use tower::{Service, ServiceExt};

use ed25519_zebra::{
    batch::{BatchVerifier, VerificationRequest},
    *,
};

fn batch_verify_n(n: usize, mut svc: BatchVerifier) {
    let mut rt = Runtime::new().unwrap();
    rt.block_on(async {
        let mut results = FuturesUnordered::new();
        for _ in 0..n {
            let sk = SecretKey::new(thread_rng());
            let pk_bytes = PublicKeyBytes::from(&sk);
            let msg = b"BatchVerifyTest";
            let sig = sk.sign(&msg[..]);
            svc.ready().await;
            results.push(svc.call((pk_bytes, sig, &msg[..])));
        }

        svc.finalize(thread_rng());

        for _ in 0..n {
            assert_eq!(results.next().await, Some(Ok(())));
        }
    });
}

#[test]
fn batch_verify_100() {
    batch_verify_n(100, BatchVerifier::default());
}
