use std::sync::Arc;
use std::mem;
use dashmap::DashMap;
use windows::Win32::System::Diagnostics::Debug::*;
use windows::Win32::System::Threading::*;
use windows::Win32::System::Memory::*;
use windows::Win32::Foundation::*;
use winapi::um::winnt::{PROCESS_ALL_ACCESS, MEM_COMMIT, PAGE_EXECUTE_READWRITE};
use crate::{ProcessInfo, InjectionType, Result, GuardError};

pub struct InjectionDetector {
    detection_cache: DashMap<u32, Vec<Detection>>,
}

#[derive(Debug, Clone)]
pub struct Detection {
    pub injection_type: InjectionType,
    pub confidence: f32,
    pub timestamp: u64,
    pub details: String,
}

impl InjectionDetector {
    pub fn new() -> Self {
        Self {
            detection_cache: DashMap::new(),
        }
    }

    pub async fn run(
        &self,
        processes: Arc<DashMap<u32, ProcessInfo>>,
        ml_engine: Arc<crate::ml::AnomalyEngine>,
    ) {
        loop {
            for entry in processes.iter() {
                let (pid, info) = entry.pair();
                
                if let Some(injection) = self.detect_injection(*pid, info).await {
                    self.detection_cache.entry(*pid)
                        .or_insert_with(Vec::new)
                        .push(injection.clone());
                    
                    if injection.confidence > 0.8 {
                        self.block_process(*pid).await;
                    }
                }
                
                if let Some(anomaly) = ml_engine.check_anomaly(*pid).await {
                    if anomaly > 0.9 {
                        self.detection_cache.entry(*pid)
                            .or_insert_with(Vec::new)
                            .push(Detection {
                                injection_type: InjectionType::ProcessHollowing,
                                confidence: anomaly,
                                timestamp: std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap()
                                    .as_secs(),
                                details: "ML anomaly detected".to_string(),
                            });
                    }
                }
            }
            
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
    }

    async fn detect_injection(&self, pid: u32, info: &ProcessInfo) -> Option<Detection> {
        if self.detect_hollowing(pid).await {
            return Some(Detection {
                injection_type: InjectionType::ProcessHollowing,
                confidence: 0.95,
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                details: format!("Process {} hollowed", info.name),
            });
        }
        
        if self.detect_thread_hijacking(pid).await {
            return Some(Detection {
                injection_type: InjectionType::ThreadHijacking,
                confidence: 0.85,
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                details: format!("Thread hijacked in {}", info.name),
            });
        }
        
        None
    }

    async fn detect_hollowing(&self, pid: u32) -> bool {
        unsafe {
            let handle = OpenProcess(
                PROCESS_ALL_ACCESS,
                false,
                pid
            ).ok();
            
            if let Some(h) = handle {
                let mut mbi = MEMORY_BASIC_INFORMATION::default();
                let mut address = 0usize;
                
                while VirtualQueryEx(
                    h,
                    Some(address as *const _),
                    &mut mbi,
                    mem::size_of::<MEMORY_BASIC_INFORMATION>()
                ) != 0 {
                    if mbi.Protect == PAGE_EXECUTE_READWRITE 
                        && mbi.State == MEM_COMMIT {
                        let _ = CloseHandle(h);
                        return true;
                    }
                    address += mbi.RegionSize;
                }
                
                let _ = CloseHandle(h);
            }
        }
        false
    }

    async fn detect_thread_hijacking(&self, pid: u32) -> bool {
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0).ok();
            
            if let Some(snap) = snapshot {
                let mut thread_entry = THREADENTRY32 {
                    dwSize: mem::size_of::<THREADENTRY32>() as u32,
                    ..Default::default()
                };
                
                if Thread32First(snap, &mut thread_entry).is_ok() {
                    loop {
                        if thread_entry.th32OwnerProcessID == pid {
                            let thread_handle = OpenThread(
                                THREAD_ALL_ACCESS,
                                false,
                                thread_entry.th32ThreadID
                            ).ok();
                            
                            if let Some(th) = thread_handle {
                                let mut context = CONTEXT::default();
                                context.ContextFlags = CONTEXT_FULL;
                                
                                if SuspendThread(th) != u32::MAX {
                                    if GetThreadContext(th, &mut context).is_ok() {
                                        #[cfg(target_arch = "x86_64")]
                                        let suspicious = context.Rip > 0x7FFFFFFF00000000;
                                        #[cfg(target_arch = "x86")]
                                        let suspicious = context.Eip > 0x80000000;
                                        
                                        let _ = ResumeThread(th);
                                        let _ = CloseHandle(th);
                                        
                                        if suspicious {
                                            let _ = CloseHandle(snap);
                                            return true;
                                        }
                                    }
                                    let _ = ResumeThread(th);
                                }
                                let _ = CloseHandle(th);
                            }
                        }
                        
                        if !Thread32Next(snap, &mut thread_entry).is_ok() {
                            break;
                        }
                    }
                }
                
                let _ = CloseHandle(snap);
            }
        }
        false
    }

    async fn block_process(&self, pid: u32) {
        unsafe {
            if let Ok(handle) = OpenProcess(PROCESS_TERMINATE, false, pid) {
                let _ = TerminateProcess(handle, 1337);
                let _ = CloseHandle(handle);
            }
        }
    }
}