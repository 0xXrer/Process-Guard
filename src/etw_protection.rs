use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use dashmap::DashMap;
use parking_lot::RwLock;
use sha2::{Sha256, Digest};
use windows::Win32::Foundation::*;
use windows::Win32::System::Memory::*;
use windows::Win32::System::Threading::*;
use windows::Win32::System::SystemServices::*;
use windows::Win32::System::Diagnostics::Debug::*;
use winapi::um::winnt::*;
use winapi::um::memoryapi::*;
use ntapi::ntmmapi::*;
use ntapi::ntpsapi::*;
use crate::{Result, GuardError};

#[derive(Debug, Clone)]
pub struct IntegrityCheckpoint {
    pub address: usize,
    pub size: usize,
    pub hash: [u8; 32],
    pub timestamp: u64,
    pub module_name: String,
    pub critical: bool,
}

#[derive(Debug, Clone)]
pub struct MemoryProtectionEvent {
    pub address: usize,
    pub size: usize,
    pub old_protection: u32,
    pub new_protection: u32,
    pub timestamp: u64,
    pub suspicious: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TamperDetection {
    EtwCallbackModified,
    NtdllUnhooked,
    SelfModification,
    MemoryProtectionChange,
    IntegrityCheckFailed,
}

pub struct EtwProtection {
    checkpoints: Arc<DashMap<usize, IntegrityCheckpoint>>,
    protection_events: Arc<RwLock<Vec<MemoryProtectionEvent>>>,
    is_monitoring: Arc<AtomicBool>,
    last_check: Arc<AtomicU64>,
    original_callbacks: Arc<RwLock<HashMap<String, usize>>>,
    ntdll_base: usize,
    ntdll_size: usize,
    self_pid: u32,
    kernel_fallback: Arc<RwLock<Option<KernelFallback>>>,
    tamper_count: Arc<AtomicU64>,
}

struct KernelFallback {
    driver_handle: HANDLE,
    minifilter_port: HANDLE,
    communication_buffer: *mut u8,
    buffer_size: usize,
}

impl EtwProtection {
    pub fn new() -> Result<Self> {
        let self_pid = unsafe { GetCurrentProcessId() };
        let (ntdll_base, ntdll_size) = Self::get_ntdll_info()?;

        let protection = Self {
            checkpoints: Arc::new(DashMap::new()),
            protection_events: Arc::new(RwLock::new(Vec::new())),
            is_monitoring: Arc::new(AtomicBool::new(false)),
            last_check: Arc::new(AtomicU64::new(0)),
            original_callbacks: Arc::new(RwLock::new(HashMap::new())),
            ntdll_base,
            ntdll_size,
            self_pid,
            kernel_fallback: Arc::new(RwLock::new(None)),
            tamper_count: Arc::new(AtomicU64::new(0)),
        };

        protection.initialize_checkpoints()?;
        protection.setup_memory_protection_hooks()?;

        Ok(protection)
    }

    pub async fn start_monitoring(&self) -> Result<()> {
        if self.is_monitoring.load(Ordering::Relaxed) {
            return Ok(());
        }

        self.is_monitoring.store(true, Ordering::Relaxed);

        let protection_clone = self.clone();
        tokio::spawn(async move {
            protection_clone.integrity_check_loop().await;
        });

        let protection_clone = self.clone();
        tokio::spawn(async move {
            protection_clone.memory_monitoring_loop().await;
        });

        let protection_clone = self.clone();
        tokio::spawn(async move {
            protection_clone.unhook_detection_loop().await;
        });

        Ok(())
    }

    async fn integrity_check_loop(&self) {
        while self.is_monitoring.load(Ordering::Relaxed) {
            let start_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis();

            if let Err(tampering) = self.perform_integrity_check().await {
                self.tamper_count.fetch_add(1, Ordering::Relaxed);
                self.handle_tamper_detection(tampering).await;
            }

            self.last_check.store(start_time as u64, Ordering::Relaxed);

            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    async fn memory_monitoring_loop(&self) {
        while self.is_monitoring.load(Ordering::Relaxed) {
            self.check_memory_protection_changes().await;
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    async fn unhook_detection_loop(&self) {
        while self.is_monitoring.load(Ordering::Relaxed) {
            if let Err(detection) = self.detect_ntdll_unhooking().await {
                self.handle_tamper_detection(detection).await;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    fn initialize_checkpoints(&self) -> Result<()> {
        self.add_etw_callback_checkpoints()?;
        self.add_critical_ntdll_functions()?;
        self.add_self_code_checkpoints()?;

        Ok(())
    }

    fn add_etw_callback_checkpoints(&self) -> Result<()> {
        unsafe {
            let ntdll = GetModuleHandleA(PCSTR(b"ntdll.dll\0".as_ptr()))
                .map_err(|_| GuardError::EtwError)?;

            let etw_functions = [
                "EtwEventWrite",
                "EtwEventRegister",
                "EtwEventUnregister",
                "NtTraceEvent",
                "NtTraceControl",
            ];

            for func_name in &etw_functions {
                if let Some(func_addr) = GetProcAddress(ntdll, PCSTR(func_name.as_ptr())) {
                    let addr = func_addr as usize;
                    let size = 64; // Enough for function prologue
                    let hash = self.calculate_memory_hash(addr, size)?;

                    self.checkpoints.insert(addr, IntegrityCheckpoint {
                        address: addr,
                        size,
                        hash,
                        timestamp: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs(),
                        module_name: format!("ntdll.{}", func_name),
                        critical: true,
                    });
                }
            }
        }

        Ok(())
    }

    fn add_critical_ntdll_functions(&self) -> Result<()> {
        unsafe {
            let ntdll = GetModuleHandleA(PCSTR(b"ntdll.dll\0".as_ptr()))
                .map_err(|_| GuardError::EtwError)?;

            let critical_functions = [
                "NtProtectVirtualMemory",
                "NtAllocateVirtualMemory",
                "NtFreeVirtualMemory",
                "NtCreateProcess",
                "NtCreateThread",
                "LdrLoadDll",
                "RtlCreateUserThread",
            ];

            for func_name in &critical_functions {
                if let Some(func_addr) = GetProcAddress(ntdll, PCSTR(func_name.as_ptr())) {
                    let addr = func_addr as usize;
                    let size = 32;
                    let hash = self.calculate_memory_hash(addr, size)?;

                    self.checkpoints.insert(addr, IntegrityCheckpoint {
                        address: addr,
                        size,
                        hash,
                        timestamp: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs(),
                        module_name: format!("ntdll.{}", func_name),
                        critical: true,
                    });
                }
            }
        }

        Ok(())
    }

    fn add_self_code_checkpoints(&self) -> Result<()> {
        unsafe {
            let module_handle = GetModuleHandleW(None)
                .map_err(|_| GuardError::EtwError)?;

            let dos_header = module_handle.0 as *const IMAGE_DOS_HEADER;
            let nt_headers = (module_handle.0 + (*dos_header).e_lfanew as isize) as *const IMAGE_NT_HEADERS64;
            let section_headers = (nt_headers as usize + std::mem::size_of::<IMAGE_NT_HEADERS64>()) as *const IMAGE_SECTION_HEADER;

            let num_sections = (*nt_headers).FileHeader.NumberOfSections;

            for i in 0..num_sections {
                let section = &*section_headers.offset(i as isize);
                let section_name = std::ffi::CStr::from_ptr(section.Name.as_ptr() as *const i8)
                    .to_string_lossy();

                if section_name == ".text" || section_name == ".rdata" {
                    let addr = module_handle.0 as usize + section.VirtualAddress as usize;
                    let size = section.Misc.VirtualSize as usize;

                    // Break large sections into chunks
                    const CHUNK_SIZE: usize = 4096;
                    for offset in (0..size).step_by(CHUNK_SIZE) {
                        let chunk_addr = addr + offset;
                        let chunk_size = std::cmp::min(CHUNK_SIZE, size - offset);
                        let hash = self.calculate_memory_hash(chunk_addr, chunk_size)?;

                        self.checkpoints.insert(chunk_addr, IntegrityCheckpoint {
                            address: chunk_addr,
                            size: chunk_size,
                            hash,
                            timestamp: SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_secs(),
                            module_name: format!("self.{}.{:x}", section_name, offset),
                            critical: section_name == ".text",
                        });
                    }
                }
            }
        }

        Ok(())
    }

    fn calculate_memory_hash(&self, address: usize, size: usize) -> Result<[u8; 32]> {
        unsafe {
            let buffer = std::slice::from_raw_parts(address as *const u8, size);
            let mut hasher = Sha256::new();
            hasher.update(buffer);
            let result = hasher.finalize();
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&result);
            Ok(hash)
        }
    }

    async fn perform_integrity_check(&self) -> Result<(), TamperDetection> {
        for checkpoint_entry in self.checkpoints.iter() {
            let checkpoint = checkpoint_entry.value();

            let current_hash = self.calculate_memory_hash(checkpoint.address, checkpoint.size)
                .map_err(|_| TamperDetection::IntegrityCheckFailed)?;

            if current_hash != checkpoint.hash {
                if checkpoint.module_name.contains("ntdll.Etw") {
                    return Err(TamperDetection::EtwCallbackModified);
                } else if checkpoint.module_name.contains("ntdll.") {
                    return Err(TamperDetection::NtdllUnhooked);
                } else if checkpoint.module_name.contains("self.") {
                    return Err(TamperDetection::SelfModification);
                } else {
                    return Err(TamperDetection::IntegrityCheckFailed);
                }
            }
        }

        Ok(())
    }

    async fn check_memory_protection_changes(&self) {
        unsafe {
            let handle = GetCurrentProcess();
            let mut mbi = MEMORY_BASIC_INFORMATION::default();
            let mut address = self.ntdll_base;

            while address < self.ntdll_base + self.ntdll_size {
                if VirtualQueryEx(
                    handle,
                    Some(address as *const _),
                    &mut mbi,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>()
                ) != 0 {
                    if mbi.Protect == PAGE_EXECUTE_READWRITE ||
                       mbi.Protect == PAGE_READWRITE {

                        let event = MemoryProtectionEvent {
                            address,
                            size: mbi.RegionSize,
                            old_protection: 0, // Would need tracking for this
                            new_protection: mbi.Protect,
                            timestamp: SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_secs(),
                            suspicious: true,
                        };

                        self.protection_events.write().push(event);
                    }

                    address += mbi.RegionSize;
                } else {
                    break;
                }
            }
        }
    }

    async fn detect_ntdll_unhooking(&self) -> Result<(), TamperDetection> {
        unsafe {
            let ntdll = GetModuleHandleA(PCSTR(b"ntdll.dll\0".as_ptr()))
                .map_err(|_| GuardError::EtwError)?;

            let functions_to_check = [
                "NtProtectVirtualMemory",
                "NtAllocateVirtualMemory",
                "LdrLoadDll",
            ];

            for func_name in &functions_to_check {
                if let Some(func_addr) = GetProcAddress(ntdll, PCSTR(func_name.as_ptr())) {
                    let prologue = std::slice::from_raw_parts(func_addr as *const u8, 16);

                    // Check for common unhooking patterns
                    if self.is_function_unhooked(prologue) {
                        return Err(TamperDetection::NtdllUnhooked);
                    }
                }
            }
        }

        Ok(())
    }

    fn is_function_unhooked(&self, prologue: &[u8]) -> bool {
        // Check for restored original bytes after unhooking
        if prologue.len() >= 5 {
            // Common unhook pattern: MOV r10, rcx; MOV eax, syscall_number
            if prologue[0] == 0x4C && prologue[1] == 0x8B && prologue[2] == 0xD1 &&
               prologue[3] == 0xB8 {
                return true;
            }

            // Another pattern: direct syscall restoration
            if prologue[0] == 0x48 && prologue[1] == 0x89 &&
               prologue[4] == 0xB8 {
                return true;
            }
        }

        false
    }

    fn setup_memory_protection_hooks(&self) -> Result<()> {
        unsafe {
            let ntdll = GetModuleHandleA(PCSTR(b"ntdll.dll\0".as_ptr()))
                .map_err(|_| GuardError::EtwError)?;

            if let Some(protect_addr) = GetProcAddress(ntdll, PCSTR(b"NtProtectVirtualMemory\0".as_ptr())) {
                // Set up inline hook for NtProtectVirtualMemory
                self.install_protection_hook(protect_addr as usize)?;
            }
        }

        Ok(())
    }

    fn install_protection_hook(&self, target_addr: usize) -> Result<()> {
        unsafe {
            let mut old_protect = PAGE_PROTECTION_FLAGS(0);

            VirtualProtect(
                target_addr as *mut _,
                16,
                PAGE_EXECUTE_READWRITE,
                &mut old_protect,
            ).map_err(|_| GuardError::EtwError)?;

            // Save original bytes
            let original_bytes = std::slice::from_raw_parts(target_addr as *const u8, 16);

            // Install minimal trampoline to monitor calls affecting our process
            let hook_bytes: [u8; 5] = [
                0xE9, // JMP rel32
                0x00, 0x00, 0x00, 0x00, // Will be calculated
            ];

            let hook_addr = Self::protection_hook_handler as *const () as usize;
            let rel_offset = (hook_addr as i32) - (target_addr as i32) - 5;

            let final_hook = [
                0xE9,
                (rel_offset & 0xFF) as u8,
                ((rel_offset >> 8) & 0xFF) as u8,
                ((rel_offset >> 16) & 0xFF) as u8,
                ((rel_offset >> 24) & 0xFF) as u8,
            ];

            std::ptr::copy_nonoverlapping(
                final_hook.as_ptr(),
                target_addr as *mut u8,
                5,
            );

            VirtualProtect(
                target_addr as *mut _,
                16,
                old_protect,
                &mut old_protect,
            ).ok();
        }

        Ok(())
    }

    extern "C" fn protection_hook_handler() {
        // Minimal monitoring - check if target is our process
        unsafe {
            let current_pid = GetCurrentProcessId();
            // Log the call but don't interfere with execution
            // This would need proper assembly trampoline in production
        }
    }

    async fn handle_tamper_detection(&self, detection: TamperDetection) {
        match detection {
            TamperDetection::EtwCallbackModified => {
                self.attempt_etw_recovery().await;
            },
            TamperDetection::NtdllUnhooked => {
                self.activate_kernel_fallback().await;
            },
            TamperDetection::SelfModification => {
                self.emergency_shutdown().await;
            },
            TamperDetection::MemoryProtectionChange => {
                self.reinforce_protection().await;
            },
            TamperDetection::IntegrityCheckFailed => {
                self.perform_deep_scan().await;
            },
        }
    }

    async fn attempt_etw_recovery(&self) {
        // Try to re-register ETW callbacks
        if let Err(_) = self.re_register_etw_callbacks().await {
            // If ETW recovery fails, switch to kernel fallback
            self.activate_kernel_fallback().await;
        }
    }

    async fn re_register_etw_callbacks(&self) -> Result<()> {
        // This would re-establish ETW session if possible
        // Implementation depends on ETW session management
        Ok(())
    }

    async fn activate_kernel_fallback(&self) {
        if let Ok(fallback) = self.setup_kernel_communication().await {
            *self.kernel_fallback.write() = Some(fallback);
        }
    }

    async fn setup_kernel_communication(&self) -> Result<KernelFallback> {
        use crate::kernel_driver::KernelDriver;

        let kernel_driver = KernelDriver::new();

        // Try to load the driver
        if kernel_driver.load_driver("C:\\ProcessGuard\\driver.sys").is_ok() {
            kernel_driver.start_monitoring()?;

            // Allocate communication buffer
            let buffer_size = 65536;
            unsafe {
                let buffer = windows::Win32::System::Memory::VirtualAlloc(
                    Some(std::ptr::null_mut()),
                    buffer_size,
                    windows::Win32::System::Memory::MEM_COMMIT | windows::Win32::System::Memory::MEM_RESERVE,
                    windows::Win32::System::Memory::PAGE_READWRITE,
                );

                if !buffer.is_null() {
                    return Ok(KernelFallback {
                        driver_handle: HANDLE(1), // Placeholder
                        minifilter_port: HANDLE(2), // Placeholder
                        communication_buffer: buffer as *mut u8,
                        buffer_size,
                    });
                }
            }
        }

        Err(GuardError::DriverError)
    }

    async fn emergency_shutdown(&self) {
        self.is_monitoring.store(false, Ordering::Relaxed);
        // Implement emergency protocols
    }

    async fn reinforce_protection(&self) {
        // Re-apply memory protections where possible
        self.refresh_checkpoints().await;
    }

    async fn perform_deep_scan(&self) {
        // Perform comprehensive integrity check
        for checkpoint_entry in self.checkpoints.iter() {
            let checkpoint = checkpoint_entry.value();
            if let Ok(current_hash) = self.calculate_memory_hash(checkpoint.address, checkpoint.size) {
                if current_hash != checkpoint.hash && checkpoint.critical {
                    self.emergency_shutdown().await;
                    break;
                }
            }
        }
    }

    async fn refresh_checkpoints(&self) {
        // Recalculate hashes for all checkpoints
        let mut updates = Vec::new();

        for mut checkpoint_entry in self.checkpoints.iter_mut() {
            let checkpoint = checkpoint_entry.value_mut();
            if let Ok(new_hash) = self.calculate_memory_hash(checkpoint.address, checkpoint.size) {
                checkpoint.hash = new_hash;
                checkpoint.timestamp = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
            }
        }
    }

    fn get_ntdll_info() -> Result<(usize, usize)> {
        unsafe {
            let ntdll = GetModuleHandleA(PCSTR(b"ntdll.dll\0".as_ptr()))
                .map_err(|_| GuardError::EtwError)?;

            let mut mbi = MEMORY_BASIC_INFORMATION::default();
            VirtualQuery(
                Some(ntdll.0 as *const _),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>()
            );

            let base = mbi.AllocationBase as usize;

            // Calculate size by walking memory regions
            let mut size = 0;
            let mut current = base;

            loop {
                if VirtualQuery(
                    Some(current as *const _),
                    &mut mbi,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>()
                ) == 0 {
                    break;
                }

                if mbi.AllocationBase != base as *mut _ {
                    break;
                }

                size += mbi.RegionSize;
                current += mbi.RegionSize;
            }

            Ok((base, size))
        }
    }

    pub fn get_tamper_count(&self) -> u64 {
        self.tamper_count.load(Ordering::Relaxed)
    }

    pub fn get_last_check_time(&self) -> u64 {
        self.last_check.load(Ordering::Relaxed)
    }

    pub fn get_protection_events(&self) -> Vec<MemoryProtectionEvent> {
        self.protection_events.read().clone()
    }

    pub fn is_kernel_fallback_active(&self) -> bool {
        self.kernel_fallback.read().is_some()
    }

    pub fn stop_monitoring(&self) {
        self.is_monitoring.store(false, Ordering::Relaxed);
    }
}

impl Clone for EtwProtection {
    fn clone(&self) -> Self {
        Self {
            checkpoints: self.checkpoints.clone(),
            protection_events: self.protection_events.clone(),
            is_monitoring: self.is_monitoring.clone(),
            last_check: self.last_check.clone(),
            original_callbacks: self.original_callbacks.clone(),
            ntdll_base: self.ntdll_base,
            ntdll_size: self.ntdll_size,
            self_pid: self.self_pid,
            kernel_fallback: self.kernel_fallback.clone(),
            tamper_count: self.tamper_count.clone(),
        }
    }
}

impl Drop for EtwProtection {
    fn drop(&mut self) {
        self.stop_monitoring();
    }
}