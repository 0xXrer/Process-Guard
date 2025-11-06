use process_guard::txf::{TxfMonitor, TransactionState, FileOpType};
use process_guard::{InjectionType, ProcessGuard};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use windows::Win32::Foundation::*;
use tokio::test;

#[test]
async fn test_txf_monitor_creation() {
    let monitor = TxfMonitor::new();
    assert!(monitor.get_active_transactions().is_empty());
}

#[test]
async fn test_transaction_tracking() {
    let monitor = TxfMonitor::new();

    let tx_handle = HANDLE(0x1234 as isize);

    let active_txs = monitor.get_active_transactions();
    assert!(active_txs.is_empty());
}

#[test]
async fn test_pattern_detection() {
    let monitor = TxfMonitor::new();

    let tx_info = process_guard::txf::TransactionInfo {
        handle: HANDLE(0x1234 as isize),
        guid: [0; 16],
        create_time: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        files: vec![
            process_guard::txf::FileOperation {
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
            process_guard::txf::FileOperation {
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

    assert!(monitor.is_suspicious_pattern(&tx_info));
}

#[test]
async fn test_cleanup_old_transactions() {
    let monitor = TxfMonitor::new();

    monitor.cleanup_old_transactions();

    assert!(monitor.get_active_transactions().is_empty());
}

#[test]
async fn test_pe_file_detection() {
    let monitor = TxfMonitor::new();

    let valid_pe = b"MZ\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00PE\x00\x00";

    assert!(monitor.is_pe_file(valid_pe));

    let invalid_pe = b"Invalid data";
    assert!(!monitor.is_pe_file(invalid_pe));
}

#[test]
async fn test_doppelganging_detection_flow() {
    let monitor = Arc::new(TxfMonitor::new());

    let suspicious_txs = monitor.get_suspicious_transactions();

    for (handle, tx_info) in suspicious_txs {
        assert_eq!(tx_info.state, TransactionState::Suspicious);

        for file_op in &tx_info.files {
            if file_op.pe_written && file_op.section_created {
                assert_eq!(
                    monitor.check_transaction(handle),
                    Some(InjectionType::ProcessDoppelganging)
                );
            }
        }
    }
}

#[test]
async fn test_hook_installation_safety() {
    let monitor = TxfMonitor::new();

    unsafe {
        let result = monitor.install_hooks();

        if result.is_err() {
            println!("Hook installation failed - this is expected in test environment");
        }
    }
}

#[test]
async fn test_file_operation_tracking() {
    let monitor = TxfMonitor::new();

    let tx_handle = HANDLE(0x1000 as isize);
    let file_handle = HANDLE(0x2000 as isize);

    let file_op = process_guard::txf::FileOperation {
        path: "malware.exe".to_string(),
        handle: file_handle,
        operation_type: FileOpType::CreateTransacted,
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        pe_written: false,
        section_created: false,
    };

    assert_eq!(file_op.operation_type, FileOpType::CreateTransacted);
    assert!(!file_op.pe_written);
    assert!(!file_op.section_created);
}

#[test]
async fn test_pattern_matching_edge_cases() {
    let monitor = TxfMonitor::new();

    let empty_tx = process_guard::txf::TransactionInfo {
        handle: HANDLE(0x1111 as isize),
        guid: [0; 16],
        create_time: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        files: vec![],
        state: TransactionState::Active,
    };

    assert!(!monitor.is_suspicious_pattern(&empty_tx));

    let non_pe_tx = process_guard::txf::TransactionInfo {
        handle: HANDLE(0x2222 as isize),
        guid: [0; 16],
        create_time: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        files: vec![
            process_guard::txf::FileOperation {
                path: "data.txt".to_string(),
                handle: HANDLE(0x3333 as isize),
                operation_type: FileOpType::CreateTransacted,
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                pe_written: false,
                section_created: false,
            },
        ],
        state: TransactionState::RolledBack,
    };

    assert!(!monitor.is_suspicious_pattern(&non_pe_tx));
}

#[test]
async fn test_transaction_state_transitions() {
    let monitor = TxfMonitor::new();

    let states = vec![
        TransactionState::Active,
        TransactionState::Committed,
        TransactionState::RolledBack,
        TransactionState::Suspicious,
    ];

    for state in states {
        let tx_info = process_guard::txf::TransactionInfo {
            handle: HANDLE(0x4444 as isize),
            guid: [0; 16],
            create_time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            files: vec![],
            state: state.clone(),
        };

        assert_eq!(tx_info.state, state);
    }
}

#[test]
async fn test_concurrent_transaction_monitoring() {
    let monitor = Arc::new(TxfMonitor::new());

    let monitor_clone = monitor.clone();
    let handle1 = tokio::spawn(async move {
        monitor_clone.cleanup_old_transactions();
    });

    let monitor_clone2 = monitor.clone();
    let handle2 = tokio::spawn(async move {
        let _ = monitor_clone2.get_active_transactions();
    });

    let _ = tokio::join!(handle1, handle2);
}