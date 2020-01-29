use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use futures::stream::{FuturesUnordered, Stream, StreamExt};
use rand::thread_rng;
use tokio::runtime::Runtime;
use tower::{Service, ServiceExt};

use ed25519_zebra::{
    batch::{BatchVerifier, VerificationRequest},
    *,
};

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

fn batch_verify(sigs: &Vec<(PublicKeyBytes, Signature)>) {
    let mut svc = BatchVerifier::default();
    for (pk_bytes, sig) in sigs.iter() {
        svc.call((*pk_bytes, *sig, b""));
    }
    svc.finalize(thread_rng());
}

fn bench_batch_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("Batch Verification");
    for n in [8usize, 16, 24, 32, 40, 48, 56, 64].iter() {
        group.throughput(Throughput::Elements(*n as u64));
        let sigs = sigs_with_distinct_pubkeys().take(*n).collect::<Vec<_>>();
        group.bench_with_input(BenchmarkId::new("Distinct Pubkeys", n), &sigs, |b, sigs| {
            b.iter(|| batch_verify(sigs))
        });
        let sigs = sigs_with_same_pubkey().take(*n).collect::<Vec<_>>();
        group.bench_with_input(BenchmarkId::new("Same Pubkey", n), &sigs, |b, sigs| {
            b.iter(|| batch_verify(sigs))
        });
    }
    group.finish();
}

criterion_group!(benches, bench_batch_verify);
criterion_main!(benches);
