use candle_core::{Device, Tensor, DType, Module};
use candle_nn::{Linear, VarBuilder, VarMap, Optimizer};
use std::sync::Arc;
use parking_lot::RwLock;
use dashmap::DashMap;

pub struct AnomalyEngine {
    model: Arc<RwLock<AnomalyModel>>,
    features_cache: DashMap<u32, ProcessFeatures>,
    device: Device,
}

struct AnomalyModel {
    encoder: Linear,
    decoder: Linear,
    latent: Linear,
}

#[derive(Debug, Clone)]
struct ProcessFeatures {
    memory_usage: f32,
    thread_count: f32,
    handle_count: f32,
    cpu_usage: f32,
    network_activity: f32,
    file_operations: f32,
    registry_operations: f32,
    injection_indicators: f32,
}

impl AnomalyEngine {
    pub fn new() -> Self {
        let device = Device::Cpu;
        let varmap = VarMap::new();
        let vs = VarBuilder::from_varmap(&varmap, DType::F32, &device);
        
        let model = AnomalyModel {
            encoder: candle_nn::linear(8, 4, vs.pp("encoder")).unwrap(),
            decoder: candle_nn::linear(4, 8, vs.pp("decoder")).unwrap(),
            latent: candle_nn::linear(4, 2, vs.pp("latent")).unwrap(),
        };

        Self {
            model: Arc::new(RwLock::new(model)),
            features_cache: DashMap::new(),
            device,
        }
    }

    pub async fn check_anomaly(&self, pid: u32) -> Option<f32> {
        let features = self.extract_features(pid).await?;
        
        let input = Tensor::new(
            &[
                features.memory_usage,
                features.thread_count,
                features.handle_count,
                features.cpu_usage,
                features.network_activity,
                features.file_operations,
                features.registry_operations,
                features.injection_indicators,
            ],
            &self.device
        ).ok()?;

        let model = self.model.read();
        
        let encoded = model.encoder.forward(&input).ok()?;
        let latent = model.latent.forward(&encoded).ok()?;
        let decoded = model.decoder.forward(&encoded).ok()?;
        
        let reconstruction_error = input.sub(&decoded).ok()?
            .sqr().ok()?
            .mean_all().ok()?
            .to_scalar::<f32>().ok()?;
        
        let anomaly_score = 1.0 / (1.0 + (-reconstruction_error * 10.0).exp());
        
        Some(anomaly_score)
    }

    async fn extract_features(&self, pid: u32) -> Option<ProcessFeatures> {
        if let Some(cached) = self.features_cache.get(&pid) {
            return Some(cached.clone());
        }
        
        let features = ProcessFeatures {
            memory_usage: self.get_memory_usage(pid).await,
            thread_count: self.get_thread_count(pid).await,
            handle_count: self.get_handle_count(pid).await,
            cpu_usage: self.get_cpu_usage(pid).await,
            network_activity: self.get_network_activity(pid).await,
            file_operations: self.get_file_operations(pid).await,
            registry_operations: self.get_registry_operations(pid).await,
            injection_indicators: self.calculate_injection_score(pid).await,
        };
        
        self.features_cache.insert(pid, features.clone());
        Some(features)
    }

    async fn get_memory_usage(&self, pid: u32) -> f32 {
        unsafe {
            use windows::Win32::System::ProcessStatus::*;
            use windows::Win32::System::Threading::*;
            
            if let Ok(handle) = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid) {
                let mut pmc = PROCESS_MEMORY_COUNTERS::default();
                pmc.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
                
                if GetProcessMemoryInfo(
                    handle,
                    &mut pmc as *mut _ as *mut _,
                    pmc.cb
                ).is_ok() {
                    let _ = CloseHandle(handle);
                    return (pmc.WorkingSetSize as f32 / 1024.0 / 1024.0).min(1000.0) / 1000.0;
                }
                let _ = CloseHandle(handle);
            }
        }
        0.0
    }

    async fn get_thread_count(&self, pid: u32) -> f32 {
        unsafe {
            use windows::Win32::System::Diagnostics::ToolHelp::*;
            
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0).ok();
            if let Some(snap) = snapshot {
                let mut count = 0u32;
                let mut thread_entry = THREADENTRY32 {
                    dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
                    ..Default::default()
                };
                
                if Thread32First(snap, &mut thread_entry).is_ok() {
                    loop {
                        if thread_entry.th32OwnerProcessID == pid {
                            count += 1;
                        }
                        if !Thread32Next(snap, &mut thread_entry).is_ok() {
                            break;
                        }
                    }
                }
                let _ = CloseHandle(snap);
                return (count as f32).min(100.0) / 100.0;
            }
        }
        0.0
    }

    async fn get_handle_count(&self, pid: u32) -> f32 {
        unsafe {
            use windows::Win32::System::Threading::*;
            use winapi::um::processthreadsapi::GetProcessHandleCount;
            
            if let Ok(handle) = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid) {
                let mut count = 0u32;
                if GetProcessHandleCount(handle.0 as _, &mut count) != 0 {
                    let _ = CloseHandle(handle);
                    return (count as f32).min(1000.0) / 1000.0;
                }
                let _ = CloseHandle(handle);
            }
        }
        0.0
    }

    async fn get_cpu_usage(&self, _pid: u32) -> f32 {
        rand::random::<f32>() * 0.5
    }

    async fn get_network_activity(&self, _pid: u32) -> f32 {
        rand::random::<f32>() * 0.3
    }

    async fn get_file_operations(&self, _pid: u32) -> f32 {
        rand::random::<f32>() * 0.2
    }

    async fn get_registry_operations(&self, _pid: u32) -> f32 {
        rand::random::<f32>() * 0.2
    }

    async fn calculate_injection_score(&self, pid: u32) -> f32 {
        let mut score = 0.0;
        
        unsafe {
            use windows::Win32::System::Memory::*;
            use windows::Win32::System::Threading::*;
            
            if let Ok(handle) = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid) {
                let mut mbi = MEMORY_BASIC_INFORMATION::default();
                let mut address = 0usize;
                
                while VirtualQueryEx(
                    handle,
                    Some(address as *const _),
                    &mut mbi,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>()
                ) != 0 {
                    if mbi.Protect == PAGE_EXECUTE_READWRITE {
                        score += 0.2;
                    }
                    if mbi.Type == MEM_PRIVATE && mbi.Protect & PAGE_EXECUTE != PAGE_PROTECTION_FLAGS(0) {
                        score += 0.1;
                    }
                    address += mbi.RegionSize;
                }
                
                let _ = CloseHandle(handle);
            }
        }
        
        score.min(1.0)
    }
}