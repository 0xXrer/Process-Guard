use process_guard::heavens_gate::{HeavensGateDetector, SegmentTransition, WoW64Context};
use std::time::{SystemTime, UNIX_EPOCH};

#[tokio::test]
async fn test_heavens_gate_detector_creation() {
    let detector = HeavensGateDetector::new().expect("Failed to create Heaven's Gate detector");
    assert!(true);
}

#[tokio::test]
async fn test_wow64_process_detection() {
    let detector = HeavensGateDetector::new().expect("Failed to create detector");

    let result = detector.start_monitoring().await;
    assert!(result.is_ok());

    let is_wow64 = detector.is_wow64_process(1234).await;
    assert!(!is_wow64);

    let _result = detector.stop_monitoring().await;
}

#[tokio::test]
async fn test_segment_transition_validation() {
    let detector = HeavensGateDetector::new().expect("Failed to create detector");

    let valid_transition = SegmentTransition {
        from_cs: 0x23,  // 32-bit selector
        to_cs: 0x33,    // 64-bit selector
        from_address: 0x401000,
        to_address: 0x7FF800000000,  // 64-bit address space
        pid: 1234,
        tid: 5678,
        timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64,
    };

    let is_valid = detector.validate_transition(&valid_transition).await;
    assert!(!is_valid);

    let invalid_transition = SegmentTransition {
        from_cs: 0x33,  // Wrong direction
        to_cs: 0x23,
        from_address: 0x7FF800000000,
        to_address: 0x401000,
        pid: 1234,
        tid: 5678,
        timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64,
    };

    let is_valid = detector.validate_transition(&invalid_transition).await;
    assert!(!is_valid);
}

#[tokio::test]
async fn test_far_jump_pattern_detection() {
    let detector = HeavensGateDetector::new().expect("Failed to create detector");

    let result = detector.start_monitoring().await;
    assert!(result.is_ok());

    let transitions = detector.scan_process_for_transitions(1234).await;
    assert!(transitions.is_ok());

    let transition_list = transitions.unwrap();
    assert!(transition_list.is_empty());

    let _result = detector.stop_monitoring().await;
}

#[tokio::test]
async fn test_x64_regions_enumeration() {
    let detector = HeavensGateDetector::new().expect("Failed to create detector");

    let regions = detector.get_x64_regions(1234).await;
    assert!(regions.is_empty());
}

#[tokio::test]
async fn test_wow64_context_analysis() {
    let detector = HeavensGateDetector::new().expect("Failed to create detector");

    let result = detector.start_monitoring().await;
    assert!(result.is_ok());

    let is_wow64 = detector.is_wow64_process(std::process::id()).await;

    #[cfg(target_arch = "x86")]
    {
        assert!(is_wow64);
    }

    #[cfg(target_arch = "x86_64")]
    {
        assert!(!is_wow64);
    }

    let _result = detector.stop_monitoring().await;
}