use windows::Win32::System::Diagnostics::Etw::*;
use windows::Win32::Foundation::*;
use windows::core::*;
use std::sync::Arc;
use parking_lot::Mutex;
use crossbeam_channel::{Sender, Receiver};
use crate::{Result, GuardError};

pub struct EtwSession {
    session_handle: TRACEHANDLE,
    events: Arc<Mutex<Vec<ProcessEvent>>>,
    tx: Sender<ProcessEvent>,
    rx: Receiver<ProcessEvent>,
}

#[derive(Debug, Clone)]
pub enum ProcessEvent {
    ProcessCreate {
        pid: u32,
        parent_pid: u32,
        image_path: String,
        timestamp: u64,
    },
    ProcessTerminate {
        pid: u32,
        exit_code: u32,
        timestamp: u64,
    },
    ImageLoad {
        pid: u32,
        base_address: u64,
        image_size: usize,
        image_path: String,
        timestamp: u64,
    },
    ThreadCreate {
        pid: u32,
        tid: u32,
        start_address: u64,
        timestamp: u64,
    },
    VirtualMemAlloc {
        pid: u32,
        base_address: u64,
        size: usize,
        protection: u32,
        timestamp: u64,
    },
}

impl EtwSession {
    pub fn new() -> Result<Self> {
        let (tx, rx) = crossbeam_channel::unbounded();
        
        Ok(Self {
            session_handle: TRACEHANDLE::default(),
            events: Arc::new(Mutex::new(Vec::new())),
            tx,
            rx,
        })
    }

    pub async fn start(&mut self) -> Result<()> {
        unsafe {
            let session_name = w!("ProcessGuardETW");
            let mut properties = EVENT_TRACE_PROPERTIES {
                Wnode: WNODE_HEADER {
                    BufferSize: std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32,
                    Guid: GUID::from_u128(0x12345678_1234_1234_1234_123456789ABC),
                    ClientContext: 1,
                    Flags: WNODE_FLAG_TRACED_GUID,
                },
                LogFileMode: EVENT_TRACE_REAL_TIME_MODE,
                FlushTimer: 0,
                EnableFlags: EVENT_TRACE_FLAG_PROCESS 
                    | EVENT_TRACE_FLAG_THREAD 
                    | EVENT_TRACE_FLAG_IMAGE_LOAD
                    | EVENT_TRACE_FLAG_VIRTUAL_ALLOC,
                LoggerNameOffset: std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32,
                ..Default::default()
            };

            let status = StartTraceW(
                &mut self.session_handle,
                session_name,
                &mut properties
            );

            if status != ERROR_SUCCESS.0 && status != ERROR_ALREADY_EXISTS.0 {
                return Err(GuardError::EtwError);
            }

            let provider_guid = GUID::from_u128(0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716);
            
            let enable_status = EnableTraceEx2(
                self.session_handle,
                &provider_guid,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                TRACE_LEVEL_VERBOSE as u8,
                0xFFFFFFFFFFFFFFFF,
                0,
                0,
                std::ptr::null()
            );

            if enable_status != ERROR_SUCCESS.0 {
                return Err(GuardError::EtwError);
            }
        }

        let events = self.events.clone();
        let tx = self.tx.clone();
        
        tokio::spawn(async move {
            Self::process_events(events, tx).await;
        });

        Ok(())
    }

    async fn process_events(events: Arc<Mutex<Vec<ProcessEvent>>>, tx: Sender<ProcessEvent>) {
        loop {
            let mut event_batch = Vec::new();
            {
                let mut events_guard = events.lock();
                event_batch.append(&mut *events_guard);
            }

            for event in event_batch {
                match &event {
                    ProcessEvent::ProcessCreate { pid, image_path, .. } => {
                        if Self::is_suspicious_process(image_path) {
                            let _ = tx.send(event.clone());
                        }
                    },
                    ProcessEvent::VirtualMemAlloc { protection, .. } => {
                        if *protection == PAGE_EXECUTE_READWRITE {
                            let _ = tx.send(event.clone());
                        }
                    },
                    _ => {
                        let _ = tx.send(event.clone());
                    }
                }
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        }
    }

    fn is_suspicious_process(path: &str) -> bool {
        let suspicious = [
            "powershell", "cmd", "wscript", "cscript", 
            "rundll32", "regsvr32", "mshta", "certutil"
        ];
        
        let lower = path.to_lowercase();
        suspicious.iter().any(|s| lower.contains(s))
    }

    pub fn get_events(&self) -> Vec<ProcessEvent> {
        self.events.lock().clone()
    }

    pub async fn stop(&mut self) -> Result<()> {
        unsafe {
            let status = StopTraceW(
                self.session_handle,
                w!("ProcessGuardETW"),
                std::ptr::null_mut()
            );
            
            if status != ERROR_SUCCESS.0 {
                return Err(GuardError::EtwError);
            }
        }
        Ok(())
    }
}

const PAGE_EXECUTE_READWRITE: u32 = 0x40;