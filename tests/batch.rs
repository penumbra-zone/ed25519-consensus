use futures::stream::{FuturesUnordered, StreamExt};
use rand::thread_rng;
use tokio::runtime::Runtime;
use tower::{Service, ServiceExt};

use ed25519_zebra::{batch::BatchVerifier, *};

#[test]
fn batch_verify_with_flushing() {
    let mut rt = Runtime::new().unwrap();
    let batch_size = 32;
    let mut svc = BatchVerifier::new(batch_size);
    rt.block_on(async {
        let mut results = FuturesUnordered::new();

        // Create 2*batch_size signatures to test flushing behavior.
        for _ in 0..(2 * batch_size) {
            let sk = SecretKey::new(thread_rng());
            let pk_bytes = PublicKeyBytes::from(&sk);
            let msg = b"BatchVerifyTest";
            let sig = sk.sign(&msg[..]);
            svc.ready().await.unwrap();
            results.push(svc.call((pk_bytes, sig, &msg[..])));
        }

        // Now the first batch_size should be ready...
        for _ in 0..batch_size {
            assert_eq!(results.next().await, Some(Ok(())));
        }
        // and dropping the service should flush the rest.
        std::mem::drop(svc);
        for _ in 0..batch_size {
            assert_eq!(results.next().await, Some(Ok(())));
        }
    });
}
