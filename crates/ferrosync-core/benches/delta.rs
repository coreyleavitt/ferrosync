//! Benchmarks for delta matching throughput.
//!
//! Measures signature computation, block matching, and delta application
//! for various file sizes and similarity levels.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use ferrosync_core::delta::{matcher, sum};
use ferrosync_core::protocol::handshake::ChecksumType;

fn generate_data(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i.wrapping_mul(7919).wrapping_add(104729) % 256) as u8).collect()
}

/// Create a modified copy with a given percentage of blocks changed.
fn generate_modified(original: &[u8], change_pct: usize) -> Vec<u8> {
    let block_size = 700;
    let num_blocks = original.len() / block_size;
    let blocks_to_change = (num_blocks * change_pct) / 100;

    let mut modified = original.to_vec();
    for i in 0..blocks_to_change {
        let offset = i * block_size;
        let end = (offset + block_size).min(modified.len());
        for b in &mut modified[offset..end] {
            *b = b.wrapping_add(1);
        }
    }
    modified
}

fn bench_compute_signatures(c: &mut Criterion) {
    let sizes: &[usize] = &[
        64 * 1024,      // 64 KiB
        1024 * 1024,    // 1 MiB
        16 * 1024 * 1024, // 16 MiB
    ];

    let algorithms = [
        ("md5", ChecksumType::Md5),
        ("blake3", ChecksumType::Blake3),
        ("xxh3", ChecksumType::Xxh3),
    ];

    let mut group = c.benchmark_group("compute_signatures");

    for &size in sizes {
        let data = generate_data(size);
        group.throughput(Throughput::Bytes(size as u64));

        for &(name, alg) in &algorithms {
            group.bench_with_input(
                BenchmarkId::new(name, size),
                &data,
                |b, data| {
                    b.iter(|| sum::compute_signatures(data, 42, alg));
                },
            );
        }
    }

    group.finish();
}

fn bench_match_blocks(c: &mut Criterion) {
    let sizes: &[usize] = &[
        64 * 1024,
        1024 * 1024,
        16 * 1024 * 1024,
    ];

    let mut group = c.benchmark_group("match_blocks_identical");

    for &size in sizes {
        let data = generate_data(size);
        let sums = sum::compute_signatures(&data, 42, ChecksumType::Md5);
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &data,
            |b, data| {
                b.iter(|| matcher::match_blocks(data, &sums, 42, ChecksumType::Md5));
            },
        );
    }

    group.finish();

    let mut group = c.benchmark_group("match_blocks_10pct_changed");

    for &size in sizes {
        let basis = generate_data(size);
        let source = generate_modified(&basis, 10);
        let sums = sum::compute_signatures(&basis, 42, ChecksumType::Md5);
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &source,
            |b, source| {
                b.iter(|| matcher::match_blocks(source, &sums, 42, ChecksumType::Md5));
            },
        );
    }

    group.finish();

    let mut group = c.benchmark_group("match_blocks_completely_different");

    for &size in sizes {
        let basis = generate_data(size);
        let source = vec![0xFFu8; size];
        let sums = sum::compute_signatures(&basis, 42, ChecksumType::Md5);
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &source,
            |b, source| {
                b.iter(|| matcher::match_blocks(source, &sums, 42, ChecksumType::Md5));
            },
        );
    }

    group.finish();
}

fn bench_apply_ops(c: &mut Criterion) {
    let sizes: &[usize] = &[
        64 * 1024,
        1024 * 1024,
    ];

    let mut group = c.benchmark_group("apply_ops");

    for &size in sizes {
        let basis = generate_data(size);
        let source = generate_modified(&basis, 10);
        let sums = sum::compute_signatures(&basis, 42, ChecksumType::Md5);
        let ops = matcher::match_blocks(&source, &sums, 42, ChecksumType::Md5);
        let blength = sums.head.blength as usize;
        let remainder = sums.head.remainder as usize;

        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &ops,
            |b, ops| {
                b.iter(|| matcher::apply_ops(&basis, ops, blength, remainder));
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_compute_signatures, bench_match_blocks, bench_apply_ops);
criterion_main!(benches);
