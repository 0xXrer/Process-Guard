use std::sync::Arc;
use dashmap::DashMap;
use parking_lot::RwLock;

use crate::utils::Result;
use crate::detection::detector::InjectionDetector;
use crate::detection::ml::AnomalyEngine;
use crate::monitoring::{etw::EtwSession, etw_protection::EtwProtection, syscall::SyscallMonitor, txf::TxfMonitor};
use crate::platform::{heavens_gate::HeavensGateDetector};
use super::types::ProcessInfo;

pub struct ProcessGuard {
    processes: Arc<DashMap<u32, ProcessInfo>>,
    detector: Arc<InjectionDetector>,
    etw_session: Arc<RwLock<EtwSession>>,
    ml_engine: Arc<AnomalyEngine>,
    txf_monitor: Arc<TxfMonitor>,
    etw_protection: Arc<EtwProtection>,
    syscall_monitor: Arc<SyscallMonitor>,
    heavens_gate_detector: Arc<HeavensGateDetector>,
}

impl ProcessGuard {
    pub async fn new() -> Result<Self> {
        let etw_session = EtwSession::new()?;
        let detector = InjectionDetector::new();
        let ml_engine = AnomalyEngine::new();
        let txf_monitor = TxfMonitor::new();
        let etw_protection = EtwProtection::new()?;
        let syscall_monitor = SyscallMonitor::new()?;
        let heavens_gate_detector = HeavensGateDetector::new()?;

        unsafe {
            crate::monitoring::txf::set_global_monitor(&txf_monitor);
            txf_monitor.install_hooks()?;
        }

        Ok(Self {
            processes: Arc::new(DashMap::new()),
            detector: Arc::new(detector),
            etw_session: Arc::new(RwLock::new(etw_session)),
            ml_engine: Arc::new(ml_engine),
            txf_monitor: Arc::new(txf_monitor),
            etw_protection: Arc::new(etw_protection),
            syscall_monitor: Arc::new(syscall_monitor),
            heavens_gate_detector: Arc::new(heavens_gate_detector),
        })
    }

    pub async fn start(&self) -> Result<()> {
        let detector = self.detector.clone();
        let processes = self.processes.clone();
        let ml_engine = self.ml_engine.clone();
        let txf_monitor = self.txf_monitor.clone();

        self.etw_protection.start_monitoring().await?;

        self.syscall_monitor.start_monitoring().await?;
        self.heavens_gate_detector.start_monitoring().await?;

        let syscall_monitor = self.syscall_monitor.clone();
        let heavens_gate_detector = self.heavens_gate_detector.clone();

        tokio::spawn(async move {
            detector.run(processes, ml_engine, txf_monitor, syscall_monitor, heavens_gate_detector).await
        });

        self.etw_session.write().start().await?;
        Ok(())
    }
}
