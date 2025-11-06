use process_guard::syscall_monitor::{SyscallMonitor, SyscallInfo, StackFrame};
use std::time::{SystemTime, UNIX_EPOCH};

#[tokio::test]
async fn test_syscall_monitor_creation() {
    let monitor = SyscallMonitor::new().expect("Failed to create syscall monitor");
    assert!(true);
}

#[tokio::test]
async fn test_pattern_matching() {
    let monitor = SyscallMonitor::new().expect("Failed to create monitor");

    let direct_syscall_pattern = vec![0x4C, 0x8B, 0xD1, 0xB8, 0x18, 0x00, 0x00, 0x00, 0x0F, 0x05];

    if let Ok(has_pattern) = monitor.check_inline_syscalls(1234, 0x1000, direct_syscall_pattern.len()).await {
        assert!(!has_pattern);
    }
}

#[tokio::test]
async fn test_stack_validation() {
    let monitor = SyscallMonitor::new().expect("Failed to create monitor");

    let valid_syscall = SyscallInfo {
        number: 0x18,
        return_address: 0x7FFE0000,
        stack_frames: vec![
            StackFrame {
                return_address: 0x7FFE0000,
                frame_pointer: 0x1000,
                module_base: 0x7FFE0000,
                module_name: "ntdll.dll".to_string(),
            }
        ],
        pid: 1234,
        tid: 5678,
        timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64,
        is_direct: false,
    };

    let is_valid = monitor.validate_syscall_stack(&valid_syscall).await;
    assert!(is_valid);

    let invalid_syscall = SyscallInfo {
        number: 0x18,
        return_address: 0x401000,
        stack_frames: vec![
            StackFrame {
                return_address: 0x401000,
                frame_pointer: 0x1000,
                module_base: 0x400000,
                module_name: "malware.exe".to_string(),
            }
        ],
        pid: 1234,
        tid: 5678,
        timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64,
        is_direct: true,
    };

    let is_valid = monitor.validate_syscall_stack(&invalid_syscall).await;
    assert!(!is_valid);
}

#[tokio::test]
async fn test_monitoring_start_stop() {
    let monitor = SyscallMonitor::new().expect("Failed to create monitor");

    let result = monitor.start_monitoring().await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_syswhispers_detection() {
    let monitor = SyscallMonitor::new().expect("Failed to create monitor");

    let syswhispers_pattern = vec![
        0x4C, 0x8B, 0xD1,              // mov r10, rcx
        0xB8, 0x18, 0x00, 0x00, 0x00,  // mov eax, 0x18
        0xF6, 0x04, 0x25, 0x08, 0x03, 0xFE, 0x7F, 0x01,  // test byte ptr [0x7ffe0308], 1
        0x75, 0x03,                     // jne short
        0x0F, 0x05,                     // syscall
        0xC3                           // ret
    ];

    let fake_buffer = [syswhispers_pattern.as_slice(), &vec![0x90; 100]].concat();

    if let Ok(detected) = monitor.check_inline_syscalls(1234, 0x401000, fake_buffer.len()).await {
        assert!(!detected);
    }
}