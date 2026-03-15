//! Benchmarks for compression backends: zlib, zstd, lz4.
//!
//! Measures both compression ratio and throughput for each backend.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use ferrosync_core::protocol::compress::{Compressor, Decompressor};

fn generate_compressible_data(size: usize) -> Vec<u8> {
    // Repeating pattern -- moderately compressible.
    (0..size).map(|i| (i % 256) as u8).collect()
}

fn generate_incompressible_data(size: usize) -> Vec<u8> {
    // Pseudo-random -- hard to compress.
    (0..size)
        .map(|i| ((i.wrapping_mul(7919).wrapping_add(104729)) % 256) as u8)
        .collect()
}

fn bench_compress(c: &mut Criterion) {
    let sizes: &[usize] = &[
        1024,        // 1 KiB
        64 * 1024,   // 64 KiB
        1024 * 1024, // 1 MiB
    ];

    let mut group = c.benchmark_group("compress_compressible");

    for &size in sizes {
        let data = generate_compressible_data(size);
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("zlib_6", size), &data, |b, data| {
            let mut comp = Compressor::new(6);
            b.iter(|| {
                comp.reset().unwrap();
                comp.compress(data).unwrap()
            });
        });

        group.bench_with_input(BenchmarkId::new("zstd_3", size), &data, |b, data| {
            let mut comp = Compressor::new_zstd(3).unwrap();
            b.iter(|| {
                comp.reset().unwrap();
                comp.compress(data).unwrap()
            });
        });

        group.bench_with_input(BenchmarkId::new("lz4", size), &data, |b, data| {
            let mut comp = Compressor::new_lz4();
            b.iter(|| comp.compress(data).unwrap());
        });
    }

    group.finish();

    let mut group = c.benchmark_group("compress_incompressible");

    for &size in sizes {
        let data = generate_incompressible_data(size);
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("zlib_6", size), &data, |b, data| {
            let mut comp = Compressor::new(6);
            b.iter(|| {
                comp.reset().unwrap();
                comp.compress(data).unwrap()
            });
        });

        group.bench_with_input(BenchmarkId::new("zstd_3", size), &data, |b, data| {
            let mut comp = Compressor::new_zstd(3).unwrap();
            b.iter(|| {
                comp.reset().unwrap();
                comp.compress(data).unwrap()
            });
        });

        group.bench_with_input(BenchmarkId::new("lz4", size), &data, |b, data| {
            let mut comp = Compressor::new_lz4();
            b.iter(|| comp.compress(data).unwrap());
        });
    }

    group.finish();
}

fn bench_decompress(c: &mut Criterion) {
    let sizes: &[usize] = &[1024, 64 * 1024, 1024 * 1024];

    let mut group = c.benchmark_group("decompress");

    for &size in sizes {
        let data = generate_compressible_data(size);
        group.throughput(Throughput::Bytes(size as u64));

        // Zlib
        {
            let mut comp = Compressor::new(6);
            let compressed = comp.compress(&data).unwrap();
            group.bench_with_input(
                BenchmarkId::new("zlib", size),
                &compressed,
                |b, compressed| {
                    let mut decomp = Decompressor::new();
                    b.iter(|| {
                        decomp.reset().unwrap();
                        decomp.decompress(compressed, size).unwrap()
                    });
                },
            );
        }

        // Zstd
        {
            let mut comp = Compressor::new_zstd(3).unwrap();
            let compressed = comp.compress(&data).unwrap();
            group.bench_with_input(
                BenchmarkId::new("zstd", size),
                &compressed,
                |b, compressed| {
                    let mut decomp = Decompressor::new_zstd().unwrap();
                    b.iter(|| {
                        decomp.reset().unwrap();
                        decomp.decompress(compressed, size).unwrap()
                    });
                },
            );
        }

        // LZ4
        {
            let mut comp = Compressor::new_lz4();
            let compressed = comp.compress(&data).unwrap();
            group.bench_with_input(
                BenchmarkId::new("lz4", size),
                &compressed,
                |b, compressed| {
                    let mut decomp = Decompressor::new_lz4();
                    b.iter(|| decomp.decompress(compressed, size).unwrap());
                },
            );
        }
    }

    group.finish();
}

criterion_group!(benches, bench_compress, bench_decompress);
criterion_main!(benches);
