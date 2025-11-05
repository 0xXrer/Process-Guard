use process_guard::{ProcessGuard, ProcessInfo};
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing_subscriber;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    println!("Process Guard v0.1.0");
    println!("Real-time process injection detection");
    println!("=====================================\n");

    let guard = Arc::new(ProcessGuard::new().await?);
    
    guard.start().await?;
    
    let api_guard = guard.clone();
    tokio::spawn(async move {
        let app = process_guard::api::create_router(api_guard).await;
        let listener = TcpListener::bind("0.0.0.0:7777").await.unwrap();
        
        println!("API Server listening on http://0.0.0.0:7777");
        axum::serve(listener, app).await.unwrap();
    });

    enumerate_processes(&guard).await;

    tokio::signal::ctrl_c().await?;
    println!("\nShutting down...");

    Ok(())
}

async fn enumerate_processes(guard: &ProcessGuard) {
    unsafe {
        use windows::Win32::System::Diagnostics::ToolHelp::*;
        use windows::Win32::Foundation::*;
        
        if let Ok(snapshot) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            let mut process_entry = PROCESSENTRY32W {
                dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                ..Default::default()
            };
            
            if Process32FirstW(snapshot, &mut process_entry).is_ok() {
                loop {
                    let name = String::from_utf16_lossy(
                        &process_entry.szExeFile[..process_entry.szExeFile.iter()
                            .position(|&x| x == 0)
                            .unwrap_or(process_entry.szExeFile.len())]
                    );
                    
                    guard.processes.insert(
                        process_entry.th32ProcessID,
                        ProcessInfo {
                            pid: process_entry.th32ProcessID,
                            name,
                            parent_pid: process_entry.th32ParentProcessID,
                            create_time: 0,
                            image_base: 0,
                            entry_point: 0,
                        }
                    );
                    
                    if !Process32NextW(snapshot, &mut process_entry).is_ok() {
                        break;
                    }
                }
            }
            
            let _ = CloseHandle(snapshot);
        }
    }
    
    println!("Monitoring {} processes", guard.processes.len());
}