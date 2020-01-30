use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use rand::thread_rng;
use tower::Service;

use ed25519_zebra::{batch::*, *};

fn sigs_with_distinct_pubkeys() -> impl Iterator<Item = (PublicKeyBytes, Signature)> {
    std::iter::repeat_with(|| {
        let sk = SecretKey::new(thread_rng());
        let pk_bytes = PublicKeyBytes::from(&sk);
        let sig = sk.sign(b"");
        (pk_bytes, sig)
    })
}

fn sigs_with_same_pubkey() -> impl Iterator<Item = (PublicKeyBytes, Signature)> {
    let sk = SecretKey::new(thread_rng());
    let pk_bytes = PublicKeyBytes::from(&sk);
    std::iter::repeat_with(move || {
        let sig = sk.sign(b"");
        (pk_bytes, sig)
    })
}

fn singleton_verify(sigs: &Vec<(PublicKeyBytes, Signature)>) {
    let mut svc = SingletonVerifier;
    for (pk_bytes, sig) in sigs.iter() {
        // this should call poll_ready but doesn't; this is OK
        // only in this specific case because it's always ready.
        svc.call((*pk_bytes, *sig, b""));
    }
}

fn batch_verify(sigs: &Vec<(PublicKeyBytes, Signature)>) {
    // Set a very large batch size to prevent intermediate flushing.
    // The batch will be flushed when svc is dropped.
    let mut svc = BatchVerifier::new(100_000);
    for (pk_bytes, sig) in sigs.iter() {
        // this should call poll_ready but doesn't; this is OK
        // only in this specific case because we don't want
        // intermediate flushing.
        svc.call((*pk_bytes, *sig, b""));
    }
}

fn bench_batch_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("Batch Verification");
    for n in [8usize, 16, 24, 32, 40, 48, 56, 64].iter() {
        group.throughput(Throughput::Elements(*n as u64));
        let sigs = sigs_with_distinct_pubkeys().take(*n).collect::<Vec<_>>();
        group.bench_with_input(
            BenchmarkId::new("Unbatched verification", n),
            &sigs,
            |b, sigs| b.iter(|| singleton_verify(sigs)),
        );
        group.bench_with_input(
            BenchmarkId::new("Signatures with Distinct Pubkeys", n),
            &sigs,
            |b, sigs| b.iter(|| batch_verify(sigs)),
        );
        let sigs = sigs_with_same_pubkey().take(*n).collect::<Vec<_>>();
        group.bench_with_input(
            BenchmarkId::new("Signatures with the Same Pubkey", n),
            &sigs,
            |b, sigs| b.iter(|| batch_verify(sigs)),
        );
    }
    group.finish();
}

criterion_group!(benches, bench_batch_verify);
criterion_main!(benches);
