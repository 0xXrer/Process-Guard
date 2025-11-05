use process_guard::{ProcessGuard, InjectionType};
use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let guard = Arc::new(ProcessGuard::new().await?);
    
    guard.start().await?;
    
    let detection_guard = guard.clone();
    tokio::spawn(async move {
        loop {
            for entry in detection_guard.detector.detection_cache.iter() {
                let (pid, detections) = entry.pair();
                for detection in detections.iter() {
                    println!(
                        "[ALERT] PID {} - {:?} (confidence: {:.2})",
                        pid, detection.injection_type, detection.confidence
                    );
                    
                    if detection.confidence > 0.9 {
                        unsafe {
                            use windows::Win32::System::Threading::*;
                            if let Ok(handle) = OpenProcess(PROCESS_TERMINATE, false, *pid) {
                                let _ = TerminateProcess(handle, 1337);
                                let _ = CloseHandle(handle);
                                println!("[BLOCKED] Process {} terminated", pid);
                            }
                        }
                    }
                }
            }
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }
    });

    println!("Process Guard active. Press Ctrl+C to exit.");
    tokio::signal::ctrl_c().await?;
    
    Ok(())
}