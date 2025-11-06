pub mod detector;
pub mod etw;
pub mod ml;
pub mod api;
pub mod txf;
pub mod cli;
pub mod etw_protection;
pub mod kernel_driver;

use std::sync::Arc;
use dashmap::DashMap;
use parking_lot::RwLock;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum GuardError {
    #[error("ETW session failed")]
    EtwError,
    #[error("Process access denied")]
    AccessDenied,
    #[error("Injection detected: {0}")]
    InjectionDetected(String),
    #[error("Kernel driver error")]
    DriverError,
}

pub type Result<T> = std::result::Result<T, GuardError>;

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub parent_pid: u32,
    pub create_time: u64,
    pub image_base: u64,
    pub entry_point: u64,
}

#[derive(Debug)]
pub enum InjectionType {
    ProcessHollowing,
    SetWindowsHookEx,
    ApcQueue,
    ThreadHijacking,
    ReflectiveDll,
    ManualMapping,
    AtomBombing,
    ShimInjection,
    ProcessDoppelganging,
}

pub struct ProcessGuard {
    processes: Arc<DashMap<u32, ProcessInfo>>,
    detector: Arc<detector::InjectionDetector>,
    etw_session: Arc<RwLock<etw::EtwSession>>,
    ml_engine: Arc<ml::AnomalyEngine>,
    txf_monitor: Arc<txf::TxfMonitor>,
    etw_protection: Arc<etw_protection::EtwProtection>,
}

impl ProcessGuard {
    pub async fn new() -> Result<Self> {
        let etw_session = etw::EtwSession::new()?;
        let detector = detector::InjectionDetector::new();
        let ml_engine = ml::AnomalyEngine::new();
        let txf_monitor = txf::TxfMonitor::new();
        let etw_protection = etw_protection::EtwProtection::new()?;

        unsafe {
            txf::set_global_monitor(&txf_monitor);
            txf_monitor.install_hooks()?;
        }

        Ok(Self {
            processes: Arc::new(DashMap::new()),
            detector: Arc::new(detector),
            etw_session: Arc::new(RwLock::new(etw_session)),
            ml_engine: Arc::new(ml_engine),
            txf_monitor: Arc::new(txf_monitor),
            etw_protection: Arc::new(etw_protection),
        })
    }

    pub async fn start(&self) -> Result<()> {
        let detector = self.detector.clone();
        let processes = self.processes.clone();
        let ml_engine = self.ml_engine.clone();
        let txf_monitor = self.txf_monitor.clone();

        // Start ETW protection first
        self.etw_protection.start_monitoring().await?;

        tokio::spawn(async move {
            detector.run(processes, ml_engine, txf_monitor).await
        });

        self.etw_session.write().start().await?;
        Ok(())
    }
}