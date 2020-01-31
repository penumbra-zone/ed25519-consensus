use futures::stream::{FuturesUnordered, StreamExt};
use rand::thread_rng;
use tokio::runtime::Runtime;
use tower::{Service, ServiceExt};

use ed25519_zebra::{batch, *};

#[test]
fn batch_verify_with_flushing() {
    let mut rt = Runtime::new().unwrap();
    let batch_size = 32;
    let mut svc = batch::BatchVerifier::new(batch_size);
    rt.block_on(async {
        let mut results = FuturesUnordered::new();

        // Create 2*batch_size signatures to test flushing behavior.
        for _ in 0..(2 * batch_size) {
            let sk = SecretKey::new(thread_rng());
            let pk_bytes = PublicKeyBytes::from(&sk);
            let msg = b"BatchVerifyTest";
            let sig = sk.sign(&msg[..]);
            svc.ready().await.unwrap();
            results.push(svc.call((pk_bytes, sig, &msg[..]).into()));
        }

        // Now the first batch_size should be ready...
        for _ in 0..batch_size {
            assert_eq!(results.next().await, Some(Ok(())));
        }
        // and manually flushing should finish the rest.
        let _ = svc.ready().await;
        let _ = svc.call(batch::Request::Flush).await;
        for _ in 0..batch_size {
            assert_eq!(results.next().await, Some(Ok(())));
        }
    });
}

// This is a bit awkward and points to a rough edge in the current design. We
// need the function to be async because we need to poll readiness of the
// Service. Ideally we would also just .await the result of svc.call also, but
// doing so means that the verification future is bound to the lifetime of svc.
// This is a problem for a number of reasons: it means that we can't call
// sign_and_verify multiple times (as the &mut moves inside the future, it's not
// accessible for other calls), but it also means that in a more realistic
// scenario where we have a Buffer or something, straight-line code in async
// blocks may maintain references to data that prevents the service from getting
// dropped, preventing manual flushing.
//
// XXX this awkwardness is perhaps solved by using service_fn to create new Services?
async fn sign_and_verify<S>(svc: &mut S) -> impl std::future::Future<Output = Result<(), Error>>
where
    for<'msg> S: Service<batch::Request<'msg>, Response = (), Error = Error>,
{
    let sk = SecretKey::new(thread_rng());
    let pk_bytes = PublicKeyBytes::from(&sk);
    svc.ready().await.unwrap();
    svc.call((pk_bytes, sk.sign(b""), b"").into())
}

#[test]
fn abstract_over_batched_and_singleton_verification() {
    let mut rt = Runtime::new().unwrap();
    rt.block_on(async {
        let mut svc = batch::BatchVerifier::new(10);
        let fut1 = sign_and_verify(&mut svc).await;
        let fut2 = sign_and_verify(&mut svc).await;
        let _ = svc.ready().await;
        let _ = svc.call(batch::Request::Flush).await;
        let result1 = fut1.await;
        let result2 = fut2.await;
        assert_eq!(result1, Ok(()));
        assert_eq!(result2, Ok(()));

        let mut svc = batch::SingletonVerifier;
        let fut1 = sign_and_verify(&mut svc).await;
        let fut2 = sign_and_verify(&mut svc).await;
        let result1 = fut1.await;
        let result2 = fut2.await;
        assert_eq!(result1, Ok(()));
        assert_eq!(result2, Ok(()));
    })
}
