use criterion::{black_box, criterion_group, criterion_main, Criterion};
use process_guard::txf::{TxfMonitor, TransactionInfo, FileOperation, FileOpType, TransactionState};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use windows::Win32::Foundation::HANDLE;

fn bench_txf_monitor_creation(c: &mut Criterion) {
    c.bench_function("txf_monitor_creation", |b| {
        b.iter(|| {
            black_box(TxfMonitor::new())
        });
    });
}

fn bench_transaction_lookup(c: &mut Criterion) {
    let monitor = TxfMonitor::new();

    c.bench_function("transaction_lookup", |b| {
        b.iter(|| {
            black_box(monitor.get_active_transactions());
        });
    });
}

fn bench_pattern_detection(c: &mut Criterion) {
    let monitor = TxfMonitor::new();

    let tx_info = TransactionInfo {
        handle: HANDLE(0x1234 as isize),
        guid: [0; 16],
        create_time: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        files: vec![
            FileOperation {
                path: "test.exe".to_string(),
                handle: HANDLE(0x5678 as isize),
                operation_type: FileOpType::CreateTransacted,
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                pe_written: true,
                section_created: false,
            },
            FileOperation {
                path: "test.exe".to_string(),
                handle: HANDLE(0x5678 as isize),
                operation_type: FileOpType::CreateSection,
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                pe_written: true,
                section_created: true,
            },
        ],
        state: TransactionState::RolledBack,
    };

    c.bench_function("pattern_detection", |b| {
        b.iter(|| {
            black_box(monitor.is_suspicious_pattern(&tx_info))
        });
    });
}

fn bench_pe_file_detection(c: &mut Criterion) {
    let monitor = TxfMonitor::new();

    let valid_pe = b"MZ\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00PE\x00\x00";

    c.bench_function("pe_file_detection", |b| {
        b.iter(|| {
            black_box(monitor.is_pe_file(valid_pe))
        });
    });
}

fn bench_cleanup_transactions(c: &mut Criterion) {
    let monitor = TxfMonitor::new();

    c.bench_function("cleanup_transactions", |b| {
        b.iter(|| {
            black_box(monitor.cleanup_old_transactions())
        });
    });
}

fn bench_suspicious_transaction_lookup(c: &mut Criterion) {
    let monitor = TxfMonitor::new();

    c.bench_function("suspicious_transaction_lookup", |b| {
        b.iter(|| {
            black_box(monitor.get_suspicious_transactions())
        });
    });
}

fn bench_transaction_check(c: &mut Criterion) {
    let monitor = TxfMonitor::new();
    let handle = HANDLE(0x1234 as isize);

    c.bench_function("transaction_check", |b| {
        b.iter(|| {
            black_box(monitor.check_transaction(handle))
        });
    });
}

fn bench_concurrent_access(c: &mut Criterion) {
    let monitor = Arc::new(TxfMonitor::new());

    c.bench_function("concurrent_access", |b| {
        b.iter(|| {
            let monitor_clone = monitor.clone();
            let _ = std::thread::spawn(move || {
                black_box(monitor_clone.get_active_transactions());
            });

            black_box(monitor.get_suspicious_transactions());
        });
    });
}

fn bench_large_file_operations(c: &mut Criterion) {
    let monitor = TxfMonitor::new();

    let mut files = Vec::new();
    for i in 0..1000 {
        files.push(FileOperation {
            path: format!("file_{}.exe", i),
            handle: HANDLE(i as isize),
            operation_type: FileOpType::CreateTransacted,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            pe_written: i % 2 == 0,
            section_created: i % 3 == 0,
        });
    }

    let tx_info = TransactionInfo {
        handle: HANDLE(0x9999 as isize),
        guid: [0; 16],
        create_time: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        files,
        state: TransactionState::RolledBack,
    };

    c.bench_function("large_file_operations_pattern_check", |b| {
        b.iter(|| {
            black_box(monitor.is_suspicious_pattern(&tx_info))
        });
    });
}

criterion_group!(
    benches,
    bench_txf_monitor_creation,
    bench_transaction_lookup,
    bench_pattern_detection,
    bench_pe_file_detection,
    bench_cleanup_transactions,
    bench_suspicious_transaction_lookup,
    bench_transaction_check,
    bench_concurrent_access,
    bench_large_file_operations
);

criterion_main!(benches);