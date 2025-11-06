use crate::{GuardError, Result};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::mem;
use parking_lot::RwLock;
use dashmap::DashMap;

#[derive(Debug, Clone)]
pub struct SegmentTransition {
    pub from_cs: u16,
    pub to_cs: u16,
    pub from_address: u64,
    pub to_address: u64,
    pub pid: u32,
    pub tid: u32,
    pub timestamp: u64,
}

#[derive(Debug, Clone)]
pub struct WoW64Context {
    pub pid: u32,
    pub is_wow64: bool,
    pub peb32_address: u64,
    pub peb64_address: u64,
    pub x64_code_regions: Vec<(u64, u64)>,
}

#[derive(Debug)]
pub struct FarJumpPattern {
    pub opcodes: Vec<u8>,
    pub mask: Vec<u8>,
    pub name: String,
    pub cs_selector: u16,
}

pub struct HeavensGateDetector {
    wow64_processes: Arc<DashMap<u32, WoW64Context>>,
    segment_transitions: Arc<Mutex<Vec<SegmentTransition>>>,
    far_jump_patterns: Vec<FarJumpPattern>,
    wow64_hooks: Arc<RwLock<HashMap<String, u64>>>,
    monitoring_active: Arc<RwLock<bool>>,
}

unsafe impl Send for HeavensGateDetector {}
unsafe impl Sync for HeavensGateDetector {}

impl HeavensGateDetector {
    pub fn new() -> Result<Self> {
        let patterns = vec![
            FarJumpPattern {
                opcodes: vec![0xEA, 0x00, 0x00, 0x00, 0x00, 0x33, 0x00],
                mask:    vec![0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00],
                name: "far_jump_x64".to_string(),
                cs_selector: 0x33,
            },
            FarJumpPattern {
                opcodes: vec![0x6A, 0x33, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x83, 0x04, 0x24, 0x05, 0xCB],
                mask:    vec![0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
                name: "push_retf_x64".to_string(),
                cs_selector: 0x33,
            },
            FarJumpPattern {
                opcodes: vec![0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0xD1, 0xFF, 0xE0],
                mask:    vec![0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
                name: "indirect_x64_call".to_string(),
                cs_selector: 0x33,
            },
        ];

        Ok(Self {
            wow64_processes: Arc::new(DashMap::new()),
            segment_transitions: Arc::new(Mutex::new(Vec::new())),
            far_jump_patterns: patterns,
            wow64_hooks: Arc::new(RwLock::new(HashMap::new())),
            monitoring_active: Arc::new(RwLock::new(false)),
        })
    }

    pub async fn start_monitoring(&self) -> Result<()> {
        *self.monitoring_active.write() = true;
        self.enumerate_wow64_processes().await?;
        self.install_wow64_hooks().await?;
        self.start_segment_monitoring().await?;
        Ok(())
    }

    pub async fn stop_monitoring(&self) -> Result<()> {
        *self.monitoring_active.write() = false;
        self.remove_wow64_hooks().await?;
        Ok(())
    }

    async fn enumerate_wow64_processes(&self) -> Result<()> {
        unsafe {
            let snapshot = windows::Win32::System::Diagnostics::ToolHelp::CreateToolhelp32Snapshot(
                windows::Win32::System::Diagnostics::ToolHelp::TH32CS_SNAPPROCESS,
                0,
            ).map_err(|_| GuardError::DriverError)?;

            let mut process_entry: windows::Win32::System::Diagnostics::ToolHelp::PROCESSENTRY32 = mem::zeroed();
            process_entry.dwSize = mem::size_of::<windows::Win32::System::Diagnostics::ToolHelp::PROCESSENTRY32>() as u32;

            if windows::Win32::System::Diagnostics::ToolHelp::Process32First(snapshot, &mut process_entry).is_ok() {
                loop {
                    if let Ok(context) = self.analyze_process_wow64(process_entry.th32ProcessID).await {
                        if context.is_wow64 {
                            self.wow64_processes.insert(process_entry.th32ProcessID, context);
                        }
                    }

                    if windows::Win32::System::Diagnostics::ToolHelp::Process32Next(snapshot, &mut process_entry).is_err() {
                        break;
                    }
                }
            }

            windows::Win32::Foundation::CloseHandle(snapshot).ok();
        }
        Ok(())
    }

    async fn analyze_process_wow64(&self, pid: u32) -> Result<WoW64Context> {
        unsafe {
            let process_handle = windows::Win32::System::Threading::OpenProcess(
                windows::Win32::System::Threading::PROCESS_QUERY_INFORMATION |
                windows::Win32::System::Threading::PROCESS_VM_READ,
                false,
                pid,
            ).map_err(|_| GuardError::AccessDenied)?;

            let mut is_wow64 = false;
            let _ = windows::Win32::System::Threading::IsWow64Process(process_handle, &mut is_wow64);

            let mut context = WoW64Context {
                pid,
                is_wow64,
                peb32_address: 0,
                peb64_address: 0,
                x64_code_regions: Vec::new(),
            };

            if is_wow64 {
                self.scan_for_x64_code_regions(process_handle, &mut context).await?;
            }

            windows::Win32::Foundation::CloseHandle(process_handle).ok();
            Ok(context)
        }
    }

    async fn scan_for_x64_code_regions(&self, process_handle: windows::Win32::Foundation::HANDLE, context: &mut WoW64Context) -> Result<()> {
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
                    memory_info.Protect == windows::Win32::System::Memory::PAGE_EXECUTE_READWRITE) &&
                   memory_info.BaseAddress as u64 > 0x7FFFFFFF {

                    let mut buffer = vec![0u8; std::cmp::min(memory_info.RegionSize, 4096)];
                    let mut bytes_read = 0;

                    if windows::Win32::System::Diagnostics::Debug::ReadProcessMemory(
                        process_handle,
                        memory_info.BaseAddress,
                        buffer.as_mut_ptr() as *mut std::ffi::c_void,
                        buffer.len(),
                        Some(&mut bytes_read),
                    ).is_ok() {
                        if self.contains_x64_instructions(&buffer[..bytes_read]) {
                            context.x64_code_regions.push((
                                memory_info.BaseAddress as u64,
                                memory_info.RegionSize as u64
                            ));
                        }
                    }
                }

                address = memory_info.BaseAddress as u64 + memory_info.RegionSize as u64;
            }
        }
        Ok(())
    }

    fn contains_x64_instructions(&self, data: &[u8]) -> bool {
        let x64_patterns = [
            &[0x48],                     // REX.W prefix
            &[0x49],                     // REX.WB prefix
            &[0x4C],                     // REX.WR prefix
            &[0x4D],                     // REX.WRB prefix
            &[0x48, 0x89],              // mov r64, r64
            &[0x48, 0x8B],              // mov r64, [r64]
        ];

        let mut x64_count = 0;
        let mut total_instructions = 0;

        for i in 0..data.len().saturating_sub(8) {
            for pattern in &x64_patterns {
                if data[i..].starts_with(pattern) {
                    x64_count += 1;
                    break;
                }
            }
            total_instructions += 1;

            if total_instructions > 100 {
                break;
            }
        }

        if total_instructions > 0 {
            let ratio = x64_count as f64 / total_instructions as f64;
            ratio > 0.1
        } else {
            false
        }
    }

    async fn install_wow64_hooks(&self) -> Result<()> {
        let functions_to_hook = [
            "Wow64SystemServiceCall",
            "Wow64TransitionFromWow64",
            "Wow64PrepareForException",
            "KiUserCallbackDispatcher",
        ];

        let mut hooks = self.wow64_hooks.write();

        for func_name in &functions_to_hook {
            if let Some(address) = self.get_function_address("wow64cpu.dll", func_name).await {
                hooks.insert(func_name.to_string(), address);
            }
        }

        Ok(())
    }

    async fn get_function_address(&self, module_name: &str, function_name: &str) -> Option<u64> {
        unsafe {
            let module_handle = windows::Win32::System::LibraryLoader::GetModuleHandleA(
                windows::core::PCSTR(format!("{}\0", module_name).as_ptr())
            ).ok()?;

            let proc_address = windows::Win32::System::LibraryLoader::GetProcAddress(
                module_handle,
                windows::core::PCSTR(format!("{}\0", function_name).as_ptr())
            )?;

            Some(proc_address as u64)
        }
    }

    async fn remove_wow64_hooks(&self) -> Result<()> {
        self.wow64_hooks.write().clear();
        Ok(())
    }

    async fn start_segment_monitoring(&self) -> Result<()> {
        Ok(())
    }

    pub async fn scan_process_for_transitions(&self, pid: u32) -> Result<Vec<SegmentTransition>> {
        if let Some(context) = self.wow64_processes.get(&pid) {
            if !context.is_wow64 {
                return Ok(vec![]);
            }

            let transitions = self.analyze_code_for_far_jumps(pid, &context.x64_code_regions).await?;
            Ok(transitions)
        } else {
            Ok(vec![])
        }
    }

    async fn analyze_code_for_far_jumps(&self, pid: u32, regions: &[(u64, u64)]) -> Result<Vec<SegmentTransition>> {
        let mut transitions = Vec::new();

        unsafe {
            let process_handle = windows::Win32::System::Threading::OpenProcess(
                windows::Win32::System::Threading::PROCESS_VM_READ,
                false,
                pid,
            ).map_err(|_| GuardError::AccessDenied)?;

            for &(base_address, size) in regions {
                let mut buffer = vec![0u8; std::cmp::min(size as usize, 8192)];
                let mut bytes_read = 0;

                if windows::Win32::System::Diagnostics::Debug::ReadProcessMemory(
                    process_handle,
                    base_address as *const std::ffi::c_void,
                    buffer.as_mut_ptr() as *mut std::ffi::c_void,
                    buffer.len(),
                    Some(&mut bytes_read),
                ).is_ok() {
                    let found_transitions = self.find_far_jumps_in_buffer(
                        &buffer[..bytes_read],
                        base_address,
                        pid
                    ).await;
                    transitions.extend(found_transitions);
                }
            }

            windows::Win32::Foundation::CloseHandle(process_handle).ok();
        }

        Ok(transitions)
    }

    async fn find_far_jumps_in_buffer(&self, data: &[u8], base_address: u64, pid: u32) -> Vec<SegmentTransition> {
        let mut transitions = Vec::new();

        for pattern in &self.far_jump_patterns {
            let mut offset = 0;
            while offset + pattern.opcodes.len() <= data.len() {
                if self.pattern_matches(&data[offset..offset + pattern.opcodes.len()],
                                       &pattern.opcodes, &pattern.mask) {

                    let transition_address = base_address + offset as u64;

                    if pattern.cs_selector == 0x33 {
                        let transition = SegmentTransition {
                            from_cs: 0x23,  // 32-bit code segment
                            to_cs: 0x33,    // 64-bit code segment
                            from_address: transition_address,
                            to_address: 0,  // Will be resolved later
                            pid,
                            tid: 0,         // Will be resolved later
                            timestamp: self.get_current_timestamp(),
                        };
                        transitions.push(transition);
                    }
                }
                offset += 1;
            }
        }

        transitions
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

    fn get_current_timestamp(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    pub async fn validate_transition(&self, transition: &SegmentTransition) -> bool {
        if transition.from_cs == 0x23 && transition.to_cs == 0x33 {
            if let Some(context) = self.wow64_processes.get(&transition.pid) {
                for &(base, size) in &context.x64_code_regions {
                    if transition.to_address >= base && transition.to_address < base + size {
                        return true;
                    }
                }
            }
        }
        false
    }

    pub async fn is_wow64_process(&self, pid: u32) -> bool {
        self.wow64_processes.get(&pid).map(|ctx| ctx.is_wow64).unwrap_or(false)
    }

    pub async fn get_x64_regions(&self, pid: u32) -> Vec<(u64, u64)> {
        self.wow64_processes.get(&pid)
            .map(|ctx| ctx.x64_code_regions.clone())
            .unwrap_or_default()
    }

    pub async fn report_heavens_gate_detection(&self, pid: u32, transition: &SegmentTransition) {
        println!("Heaven's Gate detected: PID={}, CS transition 0x{:x}->0x{:x}, Address=0x{:x}",
                pid, transition.from_cs, transition.to_cs, transition.from_address);
    }
}