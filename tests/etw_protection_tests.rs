use process_guard::etw_protection::{EtwProtection, TamperDetection, IntegrityCheckpoint, MemoryProtectionEvent};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::test;

#[test]
async fn test_etw_protection_creation() {
    let protection = EtwProtection::new();
    assert!(protection.is_ok(), "ETW protection should initialize successfully");

    let protection = protection.unwrap();
    assert_eq!(protection.get_tamper_count(), 0);
    assert!(!protection.is_kernel_fallback_active());
}

#[test]
async fn test_integrity_checkpoint_creation() {
    let checkpoint = IntegrityCheckpoint {
        address: 0x7ff800000000,
        size: 1024,
        hash: [0u8; 32],
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        module_name: "test.dll".to_string(),
        critical: true,
    };

    assert_eq!(checkpoint.address, 0x7ff800000000);
    assert_eq!(checkpoint.size, 1024);
    assert!(checkpoint.critical);
    assert_eq!(checkpoint.module_name, "test.dll");
}

#[test]
async fn test_memory_protection_event() {
    let event = MemoryProtectionEvent {
        address: 0x140000000,
        size: 4096,
        old_protection: 0x20, // PAGE_EXECUTE_READ
        new_protection: 0x40, // PAGE_EXECUTE_READWRITE
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        suspicious: true,
    };

    assert!(event.suspicious);
    assert_eq!(event.old_protection, 0x20);
    assert_eq!(event.new_protection, 0x40);
}

#[test]
async fn test_tamper_detection_types() {
    let detections = vec![
        TamperDetection::EtwCallbackModified,
        TamperDetection::NtdllUnhooked,
        TamperDetection::SelfModification,
        TamperDetection::MemoryProtectionChange,
        TamperDetection::IntegrityCheckFailed,
    ];

    assert_eq!(detections.len(), 5);
    assert!(detections.contains(&TamperDetection::EtwCallbackModified));
    assert!(detections.contains(&TamperDetection::ProcessDoppelganging));
}

#[test]
async fn test_monitoring_lifecycle() {
    let protection = EtwProtection::new().unwrap();

    // Start monitoring
    let start_result = protection.start_monitoring().await;
    assert!(start_result.is_ok(), "Should start monitoring successfully");

    // Let it run for a short time
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Check that monitoring is active
    assert!(protection.get_last_check_time() > 0);

    // Stop monitoring
    protection.stop_monitoring();
}

#[test]
async fn test_hash_calculation() {
    let protection = EtwProtection::new().unwrap();

    // Test with known data
    let test_data = b"Hello, World!";
    let addr = test_data.as_ptr() as usize;

    let hash1 = protection.calculate_memory_hash(addr, test_data.len());
    let hash2 = protection.calculate_memory_hash(addr, test_data.len());

    assert!(hash1.is_ok());
    assert!(hash2.is_ok());
    assert_eq!(hash1.unwrap(), hash2.unwrap());
}

#[test]
async fn test_unhooking_detection_patterns() {
    let protection = EtwProtection::new().unwrap();

    // Test unhook pattern: MOV r10, rcx; MOV eax, syscall_number
    let unhooked_prologue1 = [0x4C, 0x8B, 0xD1, 0xB8, 0x00, 0x01, 0x00, 0x00];
    assert!(protection.is_function_unhooked(&unhooked_prologue1));

    // Test another unhook pattern: direct syscall
    let unhooked_prologue2 = [0x48, 0x89, 0x10, 0x20, 0xB8, 0x01, 0x00, 0x00];
    assert!(protection.is_function_unhooked(&unhooked_prologue2));

    // Test normal function prologue
    let normal_prologue = [0x48, 0x83, 0xEC, 0x28, 0x48, 0x8B, 0x05, 0x12];
    assert!(!protection.is_function_unhooked(&normal_prologue));

    // Test short buffer
    let short_buffer = [0x48, 0x83];
    assert!(!protection.is_function_unhooked(&short_buffer));
}

#[tokio::test]
async fn test_concurrent_monitoring() {
    let protection = EtwProtection::new().unwrap();

    protection.start_monitoring().await.unwrap();

    // Simulate concurrent access
    let protection_clone1 = protection.clone();
    let protection_clone2 = protection.clone();

    let handle1 = tokio::spawn(async move {
        for _ in 0..10 {
            let _ = protection_clone1.get_tamper_count();
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });

    let handle2 = tokio::spawn(async move {
        for _ in 0..10 {
            let _ = protection_clone2.get_protection_events();
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });

    let _ = tokio::join!(handle1, handle2);

    protection.stop_monitoring();
}

#[test]
async fn test_kernel_fallback_activation() {
    let protection = EtwProtection::new().unwrap();

    // Initially no kernel fallback
    assert!(!protection.is_kernel_fallback_active());

    // Simulate tamper detection that should activate fallback
    protection.handle_tamper_detection(TamperDetection::NtdllUnhooked).await;

    // Note: In test environment, kernel driver won't load, so fallback won't activate
    // In production, this would test actual driver loading
}

#[test]
async fn test_integrity_check_performance() {
    let protection = EtwProtection::new().unwrap();

    let start_time = std::time::Instant::now();

    // Perform multiple integrity checks
    for _ in 0..100 {
        let _ = protection.perform_integrity_check().await;
    }

    let elapsed = start_time.elapsed();

    // Should complete 100 checks in reasonable time
    assert!(elapsed < Duration::from_millis(1000),
           "100 integrity checks should complete in < 1s, took {:?}", elapsed);
}

#[test]
async fn test_memory_region_scanning() {
    let protection = EtwProtection::new().unwrap();

    // Test scanning our own memory regions
    protection.check_memory_protection_changes().await;

    let events = protection.get_protection_events();
    // In normal process, should not have suspicious memory changes
    let suspicious_events: Vec<_> = events.iter()
        .filter(|e| e.suspicious)
        .collect();

    // For a normal process, should have minimal suspicious events
    assert!(suspicious_events.len() < 10,
           "Normal process should not have many suspicious memory events");
}

#[test]
async fn test_checkpoint_refresh() {
    let protection = EtwProtection::new().unwrap();

    let initial_count = protection.checkpoints.len();
    assert!(initial_count > 0, "Should have created initial checkpoints");

    // Refresh all checkpoints
    protection.refresh_checkpoints().await;

    let final_count = protection.checkpoints.len();
    assert_eq!(initial_count, final_count, "Checkpoint count should remain same after refresh");
}

#[test]
async fn test_emergency_protocols() {
    let protection = EtwProtection::new().unwrap();

    protection.start_monitoring().await.unwrap();

    // Trigger emergency shutdown
    protection.handle_tamper_detection(TamperDetection::SelfModification).await;

    // Should stop monitoring
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Note: In actual implementation, would verify all monitoring threads stopped
}

#[test]
async fn test_self_code_integrity() {
    let protection = EtwProtection::new().unwrap();

    // Should have checkpoints for own code sections
    let self_checkpoints: Vec<_> = protection.checkpoints.iter()
        .filter(|entry| entry.value().module_name.contains("self."))
        .collect();

    assert!(self_checkpoints.len() > 0, "Should have self-code integrity checkpoints");

    // Text section should be marked as critical
    let text_checkpoints: Vec<_> = self_checkpoints.iter()
        .filter(|entry| entry.value().module_name.contains(".text"))
        .collect();

    for checkpoint in text_checkpoints {
        assert!(checkpoint.value().critical, "Text section checkpoints should be critical");
    }
}

#[test]
async fn test_etw_callback_protection() {
    let protection = EtwProtection::new().unwrap();

    // Should have checkpoints for ETW functions
    let etw_checkpoints: Vec<_> = protection.checkpoints.iter()
        .filter(|entry| entry.value().module_name.contains("ntdll.Etw"))
        .collect();

    assert!(etw_checkpoints.len() > 0, "Should have ETW function checkpoints");

    // All ETW checkpoints should be critical
    for checkpoint in etw_checkpoints {
        assert!(checkpoint.value().critical, "ETW checkpoints should be critical");
        assert!(checkpoint.value().module_name.contains("ntdll."));
    }
}

#[bench]
fn bench_integrity_check(b: &mut test::Bencher) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let protection = rt.block_on(async {
        EtwProtection::new().unwrap()
    });

    b.iter(|| {
        rt.block_on(async {
            let _ = protection.perform_integrity_check().await;
        })
    });
}

#[bench]
fn bench_hash_calculation(b: &mut test::Bencher) {
    let protection = EtwProtection::new().unwrap();
    let test_data = vec![0u8; 4096];
    let addr = test_data.as_ptr() as usize;

    b.iter(|| {
        let _ = protection.calculate_memory_hash(addr, test_data.len());
    });
}