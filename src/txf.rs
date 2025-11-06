use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use dashmap::DashMap;
use parking_lot::RwLock;
use windows::Win32::Foundation::*;
use windows::Win32::Storage::FileSystem::*;
use windows::Win32::System::SystemServices::*;
use winapi::um::winnt::*;
use winapi::um::ktmw32::*;
use winapi::um::fileapi::*;
use winapi::shared::ntdef::*;
use ntapi::ntrtl::*;
use ntapi::nttxf::*;
use crate::{InjectionType, Result, GuardError};

#[derive(Debug, Clone)]
pub struct TransactionInfo {
    pub handle: HANDLE,
    pub guid: [u8; 16],
    pub create_time: u64,
    pub files: Vec<FileOperation>,
    pub state: TransactionState,
}

#[derive(Debug, Clone)]
pub struct FileOperation {
    pub path: String,
    pub handle: HANDLE,
    pub operation_type: FileOpType,
    pub timestamp: u64,
    pub pe_written: bool,
    pub section_created: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FileOpType {
    CreateTransacted,
    WriteFile,
    CreateSection,
    MapSection,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TransactionState {
    Active,
    Committed,
    RolledBack,
    Suspicious,
}

pub struct TxfMonitor {
    transactions: Arc<DashMap<HANDLE, TransactionInfo>>,
    file_handles: Arc<DashMap<HANDLE, String>>,
    hook_manager: Arc<RwLock<HookManager>>,
    detection_patterns: Arc<RwLock<Vec<DetectionPattern>>>,
}

#[derive(Debug)]
pub struct DetectionPattern {
    pub name: String,
    pub min_operations: usize,
    pub requires_pe: bool,
    pub requires_rollback: bool,
    pub max_time_window: u64,
}

struct HookManager {
    nt_create_transaction_original: Option<extern "system" fn() -> NTSTATUS>,
    nt_rollback_transaction_original: Option<extern "system" fn() -> NTSTATUS>,
    create_file_transacted_original: Option<extern "system" fn() -> HANDLE>,
    nt_create_section_original: Option<extern "system" fn() -> NTSTATUS>,
}

impl TxfMonitor {
    pub fn new() -> Self {
        let mut patterns = Vec::new();
        patterns.push(DetectionPattern {
            name: "Process Doppelgänging".to_string(),
            min_operations: 3,
            requires_pe: true,
            requires_rollback: true,
            max_time_window: 30,
        });

        Self {
            transactions: Arc::new(DashMap::new()),
            file_handles: Arc::new(DashMap::new()),
            hook_manager: Arc::new(RwLock::new(HookManager::new())),
            detection_patterns: Arc::new(RwLock::new(patterns)),
        }
    }

    pub unsafe fn install_hooks(&self) -> Result<()> {
        let mut hook_mgr = self.hook_manager.write();

        let ntdll = GetModuleHandleA(PCSTR(b"ntdll.dll\0".as_ptr())).unwrap();
        let kernel32 = GetModuleHandleA(PCSTR(b"kernel32.dll\0".as_ptr())).unwrap();

        if ntdll.is_invalid() || kernel32.is_invalid() {
            return Err(GuardError::DriverError);
        }

        let nt_create_transaction_addr = GetProcAddress(
            ntdll,
            PCSTR(b"NtCreateTransaction\0".as_ptr())
        );

        let nt_rollback_transaction_addr = GetProcAddress(
            ntdll,
            PCSTR(b"NtRollbackTransaction\0".as_ptr())
        );

        let create_file_transacted_addr = GetProcAddress(
            kernel32,
            PCSTR(b"CreateFileTransactedW\0".as_ptr())
        );

        let nt_create_section_addr = GetProcAddress(
            ntdll,
            PCSTR(b"NtCreateSection\0".as_ptr())
        );

        if nt_create_transaction_addr.is_some() {
            self.hook_function(
                nt_create_transaction_addr.unwrap() as *mut _,
                Self::nt_create_transaction_hook as *mut _,
                &mut hook_mgr.nt_create_transaction_original,
            )?;
        }

        if nt_rollback_transaction_addr.is_some() {
            self.hook_function(
                nt_rollback_transaction_addr.unwrap() as *mut _,
                Self::nt_rollback_transaction_hook as *mut _,
                &mut hook_mgr.nt_rollback_transaction_original,
            )?;
        }

        if create_file_transacted_addr.is_some() {
            self.hook_function(
                create_file_transacted_addr.unwrap() as *mut _,
                Self::create_file_transacted_hook as *mut _,
                &mut hook_mgr.create_file_transacted_original,
            )?;
        }

        if nt_create_section_addr.is_some() {
            self.hook_function(
                nt_create_section_addr.unwrap() as *mut _,
                Self::nt_create_section_hook as *mut _,
                &mut hook_mgr.nt_create_section_original,
            )?;
        }

        Ok(())
    }

    unsafe fn hook_function<T>(
        &self,
        target: *mut u8,
        hook: *mut u8,
        original: &mut Option<T>,
    ) -> Result<()> {
        let mut old_protect = PAGE_PROTECTION_FLAGS(0);

        if VirtualProtect(
            target as *mut _,
            5,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        ).is_err() {
            return Err(GuardError::DriverError);
        }

        let jmp_instruction: [u8; 5] = [
            0xE9,
            ((hook as isize - target as isize - 5) & 0xFF) as u8,
            (((hook as isize - target as isize - 5) >> 8) & 0xFF) as u8,
            (((hook as isize - target as isize - 5) >> 16) & 0xFF) as u8,
            (((hook as isize - target as isize - 5) >> 24) & 0xFF) as u8,
        ];

        std::ptr::copy_nonoverlapping(
            jmp_instruction.as_ptr(),
            target,
            5,
        );

        VirtualProtect(
            target as *mut _,
            5,
            old_protect,
            &mut old_protect,
        ).ok();

        Ok(())
    }

    extern "system" fn nt_create_transaction_hook(
        transaction_handle: *mut HANDLE,
        desired_access: u32,
        object_attributes: *mut OBJECT_ATTRIBUTES,
        uow: *mut GUID,
        tm_handle: HANDLE,
        create_options: u32,
        isolation_level: u32,
        isolation_flags: u32,
        timeout: *mut i64,
        description: *mut UNICODE_STRING,
    ) -> NTSTATUS {
        let result = unsafe {
            let hook_mgr = GLOBAL_MONITOR.as_ref().unwrap().hook_manager.read();
            if let Some(original) = hook_mgr.nt_create_transaction_original {
                std::mem::transmute::<_, extern "system" fn(*mut HANDLE, u32, *mut OBJECT_ATTRIBUTES, *mut GUID, HANDLE, u32, u32, u32, *mut i64, *mut UNICODE_STRING) -> NTSTATUS>(original)(
                    transaction_handle,
                    desired_access,
                    object_attributes,
                    uow,
                    tm_handle,
                    create_options,
                    isolation_level,
                    isolation_flags,
                    timeout,
                    description,
                )
            } else {
                STATUS_UNSUCCESSFUL
            }
        };

        if result == STATUS_SUCCESS && !transaction_handle.is_null() {
            unsafe {
                let handle = *transaction_handle;
                let timestamp = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();

                let mut guid_bytes = [0u8; 16];
                if !uow.is_null() {
                    std::ptr::copy_nonoverlapping(
                        uow as *const u8,
                        guid_bytes.as_mut_ptr(),
                        16,
                    );
                }

                let tx_info = TransactionInfo {
                    handle,
                    guid: guid_bytes,
                    create_time: timestamp,
                    files: Vec::new(),
                    state: TransactionState::Active,
                };

                GLOBAL_MONITOR.as_ref().unwrap()
                    .transactions
                    .insert(handle, tx_info);
            }
        }

        result
    }

    extern "system" fn nt_rollback_transaction_hook(
        transaction_handle: HANDLE,
        wait: BOOLEAN,
    ) -> NTSTATUS {
        let result = unsafe {
            let hook_mgr = GLOBAL_MONITOR.as_ref().unwrap().hook_manager.read();
            if let Some(original) = hook_mgr.nt_rollback_transaction_original {
                std::mem::transmute::<_, extern "system" fn(HANDLE, BOOLEAN) -> NTSTATUS>(original)(
                    transaction_handle,
                    wait,
                )
            } else {
                STATUS_UNSUCCESSFUL
            }
        };

        if result == STATUS_SUCCESS {
            unsafe {
                if let Some(mut tx_info) = GLOBAL_MONITOR.as_ref().unwrap()
                    .transactions.get_mut(&transaction_handle) {
                    tx_info.state = TransactionState::RolledBack;

                    if GLOBAL_MONITOR.as_ref().unwrap().is_suspicious_pattern(&tx_info) {
                        tx_info.state = TransactionState::Suspicious;
                    }
                }
            }
        }

        result
    }

    extern "system" fn create_file_transacted_hook(
        file_name: PCWSTR,
        desired_access: u32,
        share_mode: u32,
        security_attributes: *const SECURITY_ATTRIBUTES,
        creation_disposition: u32,
        flags_and_attributes: u32,
        template_file: HANDLE,
        transaction: HANDLE,
        mini_version: *const u16,
        extended_parameter: *mut std::ffi::c_void,
    ) -> HANDLE {
        let result = unsafe {
            let hook_mgr = GLOBAL_MONITOR.as_ref().unwrap().hook_manager.read();
            if let Some(original) = hook_mgr.create_file_transacted_original {
                std::mem::transmute::<_, extern "system" fn(PCWSTR, u32, u32, *const SECURITY_ATTRIBUTES, u32, u32, HANDLE, HANDLE, *const u16, *mut std::ffi::c_void) -> HANDLE>(original)(
                    file_name,
                    desired_access,
                    share_mode,
                    security_attributes,
                    creation_disposition,
                    flags_and_attributes,
                    template_file,
                    transaction,
                    mini_version,
                    extended_parameter,
                )
            } else {
                INVALID_HANDLE_VALUE
            }
        };

        if result != INVALID_HANDLE_VALUE && !transaction.is_invalid() {
            unsafe {
                let path = if !file_name.is_null() {
                    let len = (0..).take_while(|&i| *file_name.offset(i) != 0).count();
                    let slice = std::slice::from_raw_parts(file_name.as_ptr(), len);
                    String::from_utf16_lossy(slice)
                } else {
                    "unknown".to_string()
                };

                let file_op = FileOperation {
                    path: path.clone(),
                    handle: result,
                    operation_type: FileOpType::CreateTransacted,
                    timestamp: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                    pe_written: false,
                    section_created: false,
                };

                if let Some(mut tx_info) = GLOBAL_MONITOR.as_ref().unwrap()
                    .transactions.get_mut(&transaction) {
                    tx_info.files.push(file_op);
                }

                GLOBAL_MONITOR.as_ref().unwrap()
                    .file_handles
                    .insert(result, path);
            }
        }

        result
    }

    extern "system" fn nt_create_section_hook(
        section_handle: *mut HANDLE,
        desired_access: u32,
        object_attributes: *mut OBJECT_ATTRIBUTES,
        maximum_size: *mut i64,
        section_page_protection: u32,
        allocation_attributes: u32,
        file_handle: HANDLE,
    ) -> NTSTATUS {
        let result = unsafe {
            let hook_mgr = GLOBAL_MONITOR.as_ref().unwrap().hook_manager.read();
            if let Some(original) = hook_mgr.nt_create_section_original {
                std::mem::transmute::<_, extern "system" fn(*mut HANDLE, u32, *mut OBJECT_ATTRIBUTES, *mut i64, u32, u32, HANDLE) -> NTSTATUS>(original)(
                    section_handle,
                    desired_access,
                    object_attributes,
                    maximum_size,
                    section_page_protection,
                    allocation_attributes,
                    file_handle,
                )
            } else {
                STATUS_UNSUCCESSFUL
            }
        };

        if result == STATUS_SUCCESS && !file_handle.is_invalid() {
            unsafe {
                if let Some(file_path) = GLOBAL_MONITOR.as_ref().unwrap()
                    .file_handles.get(&file_handle) {

                    for mut tx_entry in GLOBAL_MONITOR.as_ref().unwrap()
                        .transactions.iter_mut() {
                        let tx_info = tx_entry.value_mut();

                        for file_op in &mut tx_info.files {
                            if file_op.handle == file_handle {
                                file_op.section_created = true;

                                if section_page_protection & PAGE_EXECUTE != 0 ||
                                   section_page_protection & PAGE_EXECUTE_READ != 0 ||
                                   section_page_protection & PAGE_EXECUTE_READWRITE != 0 {

                                    let section_op = FileOperation {
                                        path: file_path.clone(),
                                        handle: file_handle,
                                        operation_type: FileOpType::CreateSection,
                                        timestamp: SystemTime::now()
                                            .duration_since(UNIX_EPOCH)
                                            .unwrap()
                                            .as_secs(),
                                        pe_written: file_op.pe_written,
                                        section_created: true,
                                    };

                                    tx_info.files.push(section_op);
                                }
                                break;
                            }
                        }
                    }
                }
            }
        }

        result
    }

    fn is_pe_file(&self, data: &[u8]) -> bool {
        if data.len() < 64 {
            return false;
        }

        if &data[0..2] != b"MZ" {
            return false;
        }

        let pe_offset = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;

        if pe_offset + 4 > data.len() {
            return false;
        }

        &data[pe_offset..pe_offset + 4] == b"PE\0\0"
    }

    fn is_suspicious_pattern(&self, tx_info: &TransactionInfo) -> bool {
        let patterns = self.detection_patterns.read();

        for pattern in patterns.iter() {
            if self.matches_pattern(tx_info, pattern) {
                return true;
            }
        }

        false
    }

    fn matches_pattern(&self, tx_info: &TransactionInfo, pattern: &DetectionPattern) -> bool {
        if tx_info.files.len() < pattern.min_operations {
            return false;
        }

        if pattern.requires_rollback && tx_info.state != TransactionState::RolledBack {
            return false;
        }

        if pattern.requires_pe {
            if !tx_info.files.iter().any(|f| f.pe_written) {
                return false;
            }
        }

        let time_window = tx_info.files.iter()
            .map(|f| f.timestamp)
            .max()
            .unwrap_or(0) - tx_info.create_time;

        if time_window > pattern.max_time_window {
            return false;
        }

        let has_create = tx_info.files.iter()
            .any(|f| f.operation_type == FileOpType::CreateTransacted);
        let has_section = tx_info.files.iter()
            .any(|f| f.operation_type == FileOpType::CreateSection);

        has_create && has_section
    }

    pub fn check_transaction(&self, handle: HANDLE) -> Option<InjectionType> {
        if let Some(tx_info) = self.transactions.get(&handle) {
            if self.is_suspicious_pattern(&tx_info) {
                return Some(InjectionType::ProcessDoppelganging);
            }
        }
        None
    }

    pub fn cleanup_old_transactions(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.transactions.retain(|_, tx_info| {
            now - tx_info.create_time < 300
        });
    }

    pub fn get_active_transactions(&self) -> Vec<(HANDLE, TransactionInfo)> {
        self.transactions.iter()
            .filter(|entry| entry.value().state == TransactionState::Active)
            .map(|entry| (*entry.key(), entry.value().clone()))
            .collect()
    }

    pub fn get_suspicious_transactions(&self) -> Vec<(HANDLE, TransactionInfo)> {
        self.transactions.iter()
            .filter(|entry| entry.value().state == TransactionState::Suspicious)
            .map(|entry| (*entry.key(), entry.value().clone()))
            .collect()
    }
}

impl HookManager {
    fn new() -> Self {
        Self {
            nt_create_transaction_original: None,
            nt_rollback_transaction_original: None,
            create_file_transacted_original: None,
            nt_create_section_original: None,
        }
    }
}

static mut GLOBAL_MONITOR: Option<&TxfMonitor> = None;

pub unsafe fn set_global_monitor(monitor: &TxfMonitor) {
    GLOBAL_MONITOR = Some(monitor);
}