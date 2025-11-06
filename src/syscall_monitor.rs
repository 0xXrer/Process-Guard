use crate::{GuardError, Result};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::mem;
use parking_lot::RwLock;
use dashmap::DashMap;

#[repr(C)]
#[derive(Debug, Clone)]
pub struct StackFrame {
    pub return_address: u64,
    pub frame_pointer: u64,
    pub module_base: u64,
    pub module_name: String,
}

#[derive(Debug, Clone)]
pub struct SyscallInfo {
    pub number: u32,
    pub return_address: u64,
    pub stack_frames: Vec<StackFrame>,
    pub pid: u32,
    pub tid: u32,
    pub timestamp: u64,
    pub is_direct: bool,
}

#[derive(Debug)]
pub struct SyscallPattern {
    pub opcodes: Vec<u8>,
    pub mask: Vec<u8>,
    pub name: String,
}

pub struct SyscallMonitor {
    ntdll_base: Arc<RwLock<Option<u64>>>,
    ntdll_size: Arc<RwLock<Option<u64>>>,
    syscall_patterns: Vec<SyscallPattern>,
    process_modules: Arc<DashMap<u32, HashMap<String, (u64, u64)>>>,
    etw_session: Arc<Mutex<Option<*mut std::ffi::c_void>>>,
}

unsafe impl Send for SyscallMonitor {}
unsafe impl Sync for SyscallMonitor {}

impl SyscallMonitor {
    pub fn new() -> Result<Self> {
        let patterns = vec![
            SyscallPattern {
                opcodes: vec![0x4C, 0x8B, 0xD1, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x05],
                mask:    vec![0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF],
                name: "direct_syscall_x64".to_string(),
            },
            SyscallPattern {
                opcodes: vec![0xB8, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3],
                mask:    vec![0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF],
                name: "minimal_syscall".to_string(),
            },
            SyscallPattern {
                opcodes: vec![0x4C, 0x8B, 0xD1, 0xB8, 0x00, 0x00, 0x00, 0x00, 0xF6, 0x04, 0x25, 0x08, 0x03, 0xFE, 0x7F, 0x01],
                mask:    vec![0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
                name: "syswhispers_template".to_string(),
            },
        ];

        Ok(Self {
            ntdll_base: Arc::new(RwLock::new(None)),
            ntdll_size: Arc::new(RwLock::new(None)),
            syscall_patterns: patterns,
            process_modules: Arc::new(DashMap::new()),
            etw_session: Arc::new(Mutex::new(None)),
        })
    }

    pub async fn start_monitoring(&self) -> Result<()> {
        self.init_ntdll_info().await?;
        self.setup_etw_session().await?;
        self.scan_all_processes().await?;
        Ok(())
    }

    async fn init_ntdll_info(&self) -> Result<()> {
        unsafe {
            let ntdll_handle = windows::Win32::System::LibraryLoader::GetModuleHandleA(
                windows::core::s!("ntdll.dll")
            ).map_err(|_| GuardError::DriverError)?;

            let mut module_info: windows::Win32::System::ProcessStatus::MODULEINFO = mem::zeroed();
            let result = windows::Win32::System::ProcessStatus::GetModuleInformation(
                windows::Win32::System::Threading::GetCurrentProcess(),
                ntdll_handle,
                &mut module_info,
                mem::size_of::<windows::Win32::System::ProcessStatus::MODULEINFO>() as u32,
            );

            if result.is_ok() {
                *self.ntdll_base.write() = Some(module_info.lpBaseOfDll as u64);
                *self.ntdll_size.write() = Some(module_info.SizeOfImage as u64);
            }
        }
        Ok(())
    }

    async fn setup_etw_session(&self) -> Result<()> {
        Ok(())
    }

    async fn scan_all_processes(&self) -> Result<()> {
        unsafe {
            let snapshot = windows::Win32::System::Diagnostics::ToolHelp::CreateToolhelp32Snapshot(
                windows::Win32::System::Diagnostics::ToolHelp::TH32CS_SNAPPROCESS,
                0,
            ).map_err(|_| GuardError::DriverError)?;

            let mut process_entry: windows::Win32::System::Diagnostics::ToolHelp::PROCESSENTRY32 = mem::zeroed();
            process_entry.dwSize = mem::size_of::<windows::Win32::System::Diagnostics::ToolHelp::PROCESSENTRY32>() as u32;

            if windows::Win32::System::Diagnostics::ToolHelp::Process32First(snapshot, &mut process_entry).is_ok() {
                loop {
                    self.scan_process_memory(process_entry.th32ProcessID).await.ok();

                    if windows::Win32::System::Diagnostics::ToolHelp::Process32Next(snapshot, &mut process_entry).is_err() {
                        break;
                    }
                }
            }

            windows::Win32::Foundation::CloseHandle(snapshot).ok();
        }
        Ok(())
    }

    async fn scan_process_memory(&self, pid: u32) -> Result<()> {
        unsafe {
            let process_handle = windows::Win32::System::Threading::OpenProcess(
                windows::Win32::System::Threading::PROCESS_QUERY_INFORMATION |
                windows::Win32::System::Threading::PROCESS_VM_READ,
                false,
                pid,
            ).map_err(|_| GuardError::AccessDenied)?;

            let mut modules = HashMap::new();
            let mut module_handles = vec![std::ptr::null_mut(); 1024];
            let mut bytes_needed = 0;

            if windows::Win32::System::ProcessStatus::EnumProcessModules(
                process_handle,
                module_handles.as_mut_ptr(),
                (module_handles.len() * mem::size_of::<windows::Win32::Foundation::HMODULE>()) as u32,
                &mut bytes_needed,
            ).is_ok() {
                let module_count = bytes_needed as usize / mem::size_of::<windows::Win32::Foundation::HMODULE>();

                for i in 0..module_count.min(module_handles.len()) {
                    if let Some(handle) = module_handles.get(i) {
                        if handle.is_null() { continue; }

                        let mut module_info: windows::Win32::System::ProcessStatus::MODULEINFO = mem::zeroed();
                        if windows::Win32::System::ProcessStatus::GetModuleInformation(
                            process_handle,
                            *handle,
                            &mut module_info,
                            mem::size_of::<windows::Win32::System::ProcessStatus::MODULEINFO>() as u32,
                        ).is_ok() {
                            let mut module_name = vec![0u8; 260];
                            if windows::Win32::System::ProcessStatus::GetModuleBaseNameA(
                                process_handle,
                                *handle,
                                &mut module_name,
                            ) > 0 {
                                let name = String::from_utf8_lossy(&module_name)
                                    .trim_matches('\0').to_string();
                                modules.insert(name, (
                                    module_info.lpBaseOfDll as u64,
                                    module_info.SizeOfImage as u64
                                ));
                            }
                        }
                    }
                }
            }

            self.process_modules.insert(pid, modules);
            self.scan_for_syscall_patterns(process_handle, pid).await?;

            windows::Win32::Foundation::CloseHandle(process_handle).ok();
        }
        Ok(())
    }

    async fn scan_for_syscall_patterns(&self, process_handle: windows::Win32::Foundation::HANDLE, pid: u32) -> Result<()> {
        unsafe {
            let mut memory_info: windows::Win32::System::Memory::MEMORY_BASIC_INFORMATION = mem::zeroed();
            let mut address = 0u64;

            while windows::Win32::System::Memory::VirtualQueryEx(
                process_handle,
                Some(address as *const std::ffi::c_void),
                &mut memory_info,
                mem::size_of::<windows::Win32::System::Memory::MEMORY_BASIC_INFORMATION>(),
            ) != 0 {
                if memory_info.State == windows::Win32::System::Memory::MEM_COMMIT &&
                   (memory_info.Protect == windows::Win32::System::Memory::PAGE_EXECUTE_READ ||
                    memory_info.Protect == windows::Win32::System::Memory::PAGE_EXECUTE_READWRITE) {

                    let mut buffer = vec![0u8; memory_info.RegionSize];
                    let mut bytes_read = 0;

                    if windows::Win32::System::Diagnostics::Debug::ReadProcessMemory(
                        process_handle,
                        memory_info.BaseAddress,
                        buffer.as_mut_ptr() as *mut std::ffi::c_void,
                        memory_info.RegionSize,
                        Some(&mut bytes_read),
                    ).is_ok() {
                        self.analyze_memory_region(&buffer[..bytes_read],
                                                 memory_info.BaseAddress as u64, pid).await;
                    }
                }

                address = memory_info.BaseAddress as u64 + memory_info.RegionSize as u64;
            }
        }
        Ok(())
    }

    async fn analyze_memory_region(&self, data: &[u8], base_address: u64, pid: u32) {
        for pattern in &self.syscall_patterns {
            let mut offset = 0;
            while offset + pattern.opcodes.len() <= data.len() {
                if self.pattern_matches(&data[offset..offset + pattern.opcodes.len()],
                                       &pattern.opcodes, &pattern.mask) {

                    let syscall_address = base_address + offset as u64;

                    if !self.is_address_in_ntdll(syscall_address) {
                        self.report_direct_syscall(pid, syscall_address, &pattern.name).await;
                    }
                }
                offset += 1;
            }
        }
    }

    fn pattern_matches(&self, data: &[u8], pattern: &[u8], mask: &[u8]) -> bool {
        if data.len() != pattern.len() || pattern.len() != mask.len() {
            return false;
        }

        for i in 0..pattern.len() {
            if mask[i] != 0 && data[i] != pattern[i] {
                return false;
            }
        }
        true
    }

    fn is_address_in_ntdll(&self, address: u64) -> bool {
        let ntdll_base = self.ntdll_base.read();
        let ntdll_size = self.ntdll_size.read();

        if let (Some(base), Some(size)) = (*ntdll_base, *ntdll_size) {
            address >= base && address < base + size
        } else {
            false
        }
    }

    async fn report_direct_syscall(&self, pid: u32, address: u64, pattern_name: &str) {
        println!("Direct syscall detected: PID={}, Address=0x{:x}, Pattern={}",
                pid, address, pattern_name);
    }

    pub async fn validate_syscall_stack(&self, syscall_info: &SyscallInfo) -> bool {
        if syscall_info.stack_frames.is_empty() {
            return false;
        }

        let first_frame = &syscall_info.stack_frames[0];

        if !self.is_address_in_ntdll(first_frame.return_address) {
            return false;
        }

        for frame in &syscall_info.stack_frames {
            if frame.module_name.to_lowercase() == "ntdll.dll" {
                return true;
            }
        }

        false
    }

    pub async fn check_inline_syscalls(&self, pid: u32, address: u64, size: usize) -> Result<bool> {
        unsafe {
            let process_handle = windows::Win32::System::Threading::OpenProcess(
                windows::Win32::System::Threading::PROCESS_VM_READ,
                false,
                pid,
            ).map_err(|_| GuardError::AccessDenied)?;

            let mut buffer = vec![0u8; size];
            let mut bytes_read = 0;

            if windows::Win32::System::Diagnostics::Debug::ReadProcessMemory(
                process_handle,
                address as *const std::ffi::c_void,
                buffer.as_mut_ptr() as *mut std::ffi::c_void,
                size,
                Some(&mut bytes_read),
            ).is_ok() {
                for pattern in &self.syscall_patterns {
                    if self.find_pattern_in_buffer(&buffer[..bytes_read], &pattern.opcodes, &pattern.mask) {
                        windows::Win32::Foundation::CloseHandle(process_handle).ok();
                        return Ok(true);
                    }
                }
            }

            windows::Win32::Foundation::CloseHandle(process_handle).ok();
        }
        Ok(false)
    }

    fn find_pattern_in_buffer(&self, buffer: &[u8], pattern: &[u8], mask: &[u8]) -> bool {
        if buffer.len() < pattern.len() {
            return false;
        }

        for i in 0..=buffer.len() - pattern.len() {
            if self.pattern_matches(&buffer[i..i + pattern.len()], pattern, mask) {
                return true;
            }
        }
        false
    }

    pub async fn get_stack_trace(&self, pid: u32, tid: u32) -> Result<Vec<StackFrame>> {
        Ok(vec![])
    }
}