//! Benchmarks for checksum algorithms: MD4, MD5, BLAKE3, XXH3, XXH128.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use ferrosync_core::delta::ProtocolContext;
use ferrosync_core::protocol::handshake::ChecksumType;

fn ctx(seed: i32, ct: ChecksumType) -> ProtocolContext {
    ProtocolContext {
        seed,
        checksum_type: ct,
        char_offset: 0,
        proper_seed_order: true,
    }
}

fn generate_data(size: usize) -> Vec<u8> {
    (0..size)
        .map(|i| (i.wrapping_mul(7919).wrapping_add(104729) % 256) as u8)
        .collect()
}

fn bench_checksum2(c: &mut Criterion) {
    let sizes: &[usize] = &[
        1024,             // 1 KiB
        64 * 1024,        // 64 KiB
        1024 * 1024,      // 1 MiB
        16 * 1024 * 1024, // 16 MiB
    ];

    let algorithms = [
        ("md4", ChecksumType::Md4),
        ("md5", ChecksumType::Md5),
        ("blake3", ChecksumType::Blake3),
        ("xxh3", ChecksumType::Xxh3),
        ("xxh128", ChecksumType::Xxh128),
    ];

    let mut group = c.benchmark_group("checksum2");

    for &size in sizes {
        let data = generate_data(size);
        group.throughput(Throughput::Bytes(size as u64));

        for &(name, alg) in &algorithms {
            group.bench_with_input(BenchmarkId::new(name, size), &data, |b, data| {
                b.iter(|| ferrosync_core::delta::checksum::checksum2(data, &ctx(42, alg)));
            });
        }
    }

    group.finish();
}

fn bench_file_checksum(c: &mut Criterion) {
    let sizes: &[usize] = &[1024, 64 * 1024, 1024 * 1024, 16 * 1024 * 1024];

    let algorithms = [
        ("md4", ChecksumType::Md4),
        ("md5", ChecksumType::Md5),
        ("blake3", ChecksumType::Blake3),
        ("xxh3", ChecksumType::Xxh3),
        ("xxh128", ChecksumType::Xxh128),
    ];

    let mut group = c.benchmark_group("file_checksum");

    for &size in sizes {
        let data = generate_data(size);
        group.throughput(Throughput::Bytes(size as u64));

        for &(name, alg) in &algorithms {
            group.bench_with_input(BenchmarkId::new(name, size), &data, |b, data| {
                b.iter(|| ferrosync_core::delta::checksum::file_checksum(data, &ctx(42, alg)));
            });
        }
    }

    group.finish();
}

fn bench_rolling_checksum(c: &mut Criterion) {
    let sizes: &[usize] = &[1024, 64 * 1024, 1024 * 1024];

    let mut group = c.benchmark_group("rolling_checksum");

    for &size in sizes {
        let data = generate_data(size);
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("checksum1", size), &data, |b, data| {
            b.iter(|| {
                ferrosync_core::delta::checksum::checksum1(
                    data,
                    ferrosync_core::delta::checksum::CHAR_OFFSET_V30,
                )
            });
        });

        group.bench_with_input(BenchmarkId::new("rolling_slide", size), &data, |b, data| {
            b.iter(|| {
                let block_len = 700;
                if data.len() < block_len + 1 {
                    return;
                }
                let mut rc = ferrosync_core::delta::checksum::RollingChecksum::new(
                    ferrosync_core::delta::checksum::CHAR_OFFSET_V30,
                );
                rc.compute(&data[..block_len]);
                for i in 0..data.len() - block_len - 1 {
                    rc.roll(data[i], data[i + block_len]);
                }
                std::hint::black_box(rc.digest());
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_checksum2,
    bench_file_checksum,
    bench_rolling_checksum
);
criterion_main!(benches);
