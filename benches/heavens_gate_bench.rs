use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use process_guard::heavens_gate::{HeavensGateDetector, SegmentTransition};
use std::time::{SystemTime, UNIX_EPOCH};

fn bench_wow64_detection(c: &mut Criterion) {
    let detector = HeavensGateDetector::new().expect("Failed to create detector");
    let runtime = tokio::runtime::Runtime::new().unwrap();

    runtime.block_on(async {
        detector.start_monitoring().await.expect("Failed to start monitoring");
    });

    c.bench_function("wow64_process_check", |b| {
        b.to_async(&runtime).iter(|| async {
            let result = detector.is_wow64_process(black_box(1234)).await;
            black_box(result)
        });
    });
}

fn bench_transition_scanning(c: &mut Criterion) {
    let detector = HeavensGateDetector::new().expect("Failed to create detector");
    let runtime = tokio::runtime::Runtime::new().unwrap();

    runtime.block_on(async {
        detector.start_monitoring().await.expect("Failed to start monitoring");
    });

    let mut group = c.benchmark_group("transition_scanning");

    for process_count in [1, 5, 10, 25].iter() {
        group.bench_with_input(
            BenchmarkId::new("scan_processes", process_count),
            process_count,
            |b, &count| {
                b.to_async(&runtime).iter(|| async {
                    for i in 0..count {
                        let result = detector.scan_process_for_transitions(black_box(1234 + i)).await;
                        black_box(result).ok();
                    }
                });
            },
        );
    }

    group.finish();
}

fn bench_transition_validation(c: &mut Criterion) {
    let detector = HeavensGateDetector::new().expect("Failed to create detector");
    let runtime = tokio::runtime::Runtime::new().unwrap();

    runtime.block_on(async {
        detector.start_monitoring().await.expect("Failed to start monitoring");
    });

    let transition = SegmentTransition {
        from_cs: 0x23,
        to_cs: 0x33,
        from_address: 0x401000,
        to_address: 0x7FF800000000,
        pid: 1234,
        tid: 5678,
        timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64,
    };

    c.bench_function("transition_validation", |b| {
        b.to_async(&runtime).iter(|| async {
            let result = detector.validate_transition(black_box(&transition)).await;
            black_box(result)
        });
    });
}

fn bench_pattern_detection(c: &mut Criterion) {
    let detector = HeavensGateDetector::new().expect("Failed to create detector");
    let runtime = tokio::runtime::Runtime::new().unwrap();

    runtime.block_on(async {
        detector.start_monitoring().await.expect("Failed to start monitoring");
    });

    let mut group = c.benchmark_group("pattern_detection");

    for buffer_size in [1024, 4096, 8192, 16384].iter() {
        group.bench_with_input(
            BenchmarkId::new("far_jump_patterns", buffer_size),
            buffer_size,
            |b, _size| {
                b.to_async(&runtime).iter(|| async {
                    let result = detector.scan_process_for_transitions(black_box(1234)).await;
                    black_box(result)
                });
            },
        );
    }

    group.finish();
}

fn bench_x64_region_enumeration(c: &mut Criterion) {
    let detector = HeavensGateDetector::new().expect("Failed to create detector");
    let runtime = tokio::runtime::Runtime::new().unwrap();

    runtime.block_on(async {
        detector.start_monitoring().await.expect("Failed to start monitoring");
    });

    c.bench_function("x64_regions", |b| {
        b.to_async(&runtime).iter(|| async {
            let result = detector.get_x64_regions(black_box(1234)).await;
            black_box(result)
        });
    });
}

fn bench_monitoring_lifecycle(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("start_stop_monitoring", |b| {
        b.to_async(&runtime).iter(|| async {
            let detector = HeavensGateDetector::new().expect("Failed to create detector");

            let start_result = detector.start_monitoring().await;
            black_box(start_result).ok();

            let stop_result = detector.stop_monitoring().await;
            black_box(stop_result).ok();
        });
    });
}

criterion_group!(
    heavens_gate_benches,
    bench_wow64_detection,
    bench_transition_scanning,
    bench_transition_validation,
    bench_pattern_detection,
    bench_x64_region_enumeration,
    bench_monitoring_lifecycle
);
criterion_main!(heavens_gate_benches);