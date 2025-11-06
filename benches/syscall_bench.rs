use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use process_guard::syscall_monitor::{SyscallMonitor, SyscallInfo, StackFrame};
use std::time::{SystemTime, UNIX_EPOCH};

fn bench_pattern_matching(c: &mut Criterion) {
    let monitor = SyscallMonitor::new().expect("Failed to create monitor");
    let runtime = tokio::runtime::Runtime::new().unwrap();

    let mut group = c.benchmark_group("pattern_matching");

    for buffer_size in [256, 1024, 4096, 16384].iter() {
        group.bench_with_input(
            BenchmarkId::new("inline_syscalls", buffer_size),
            buffer_size,
            |b, &size| {
                b.to_async(&runtime).iter(|| async {
                    let result = monitor.check_inline_syscalls(
                        black_box(1234),
                        black_box(0x401000),
                        black_box(size)
                    ).await;
                    black_box(result)
                });
            },
        );
    }

    group.finish();
}

fn bench_stack_validation(c: &mut Criterion) {
    let monitor = SyscallMonitor::new().expect("Failed to create monitor");
    let runtime = tokio::runtime::Runtime::new().unwrap();

    let syscall_info = SyscallInfo {
        number: 0x18,
        return_address: 0x7FFE0000,
        stack_frames: vec![
            StackFrame {
                return_address: 0x7FFE0000,
                frame_pointer: 0x1000,
                module_base: 0x7FFE0000,
                module_name: "ntdll.dll".to_string(),
            },
            StackFrame {
                return_address: 0x401000,
                frame_pointer: 0x2000,
                module_base: 0x400000,
                module_name: "test.exe".to_string(),
            },
        ],
        pid: 1234,
        tid: 5678,
        timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64,
        is_direct: false,
    };

    c.bench_function("stack_validation", |b| {
        b.to_async(&runtime).iter(|| async {
            let result = monitor.validate_syscall_stack(black_box(&syscall_info)).await;
            black_box(result)
        });
    });
}

fn bench_memory_scanning(c: &mut Criterion) {
    let monitor = SyscallMonitor::new().expect("Failed to create monitor");
    let runtime = tokio::runtime::Runtime::new().unwrap();

    let mut group = c.benchmark_group("memory_scanning");

    for region_count in [1, 5, 10, 50].iter() {
        group.bench_with_input(
            BenchmarkId::new("scan_regions", region_count),
            region_count,
            |b, &count| {
                b.to_async(&runtime).iter(|| async {
                    for _ in 0..count {
                        let result = monitor.check_inline_syscalls(
                            black_box(1234),
                            black_box(0x401000),
                            black_box(4096)
                        ).await;
                        black_box(result).ok();
                    }
                });
            },
        );
    }

    group.finish();
}

fn bench_monitoring_overhead(c: &mut Criterion) {
    let monitor = SyscallMonitor::new().expect("Failed to create monitor");
    let runtime = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("monitoring_startup", |b| {
        b.to_async(&runtime).iter(|| async {
            let result = monitor.start_monitoring().await;
            black_box(result)
        });
    });
}

criterion_group!(
    syscall_benches,
    bench_pattern_matching,
    bench_stack_validation,
    bench_memory_scanning,
    bench_monitoring_overhead
);
criterion_main!(syscall_benches);