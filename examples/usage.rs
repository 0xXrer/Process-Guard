use process_guard::{ProcessGuard, ProcessInfo, InjectionType};
use std::time::Duration;
use tokio::time;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("Process Guard Usage Examples");
    println!("============================\n");

    basic_monitoring().await?;
    targeted_scanning().await?;
    custom_detection().await?;
    api_integration().await?;

    Ok(())
}

async fn basic_monitoring() -> anyhow::Result<()> {
    println!("1. Basic Monitoring");
    println!("------------------");

    let guard = ProcessGuard::new().await?;

    println!("🛡️  Starting Process Guard...");
    guard.start().await?;

    println!("   Monitoring all processes for 10 seconds...");
    time::sleep(Duration::from_secs(10)).await;

    println!("✅ Monitoring complete\n");
    Ok(())
}

async fn targeted_scanning() -> anyhow::Result<()> {
    println!("2. Targeted Process Scanning");
    println!("---------------------------");

    let guard = ProcessGuard::new().await?;
    guard.start().await?;

    let target_processes = vec![
        get_process_by_name("notepad.exe").await,
        get_process_by_name("calc.exe").await,
        get_process_by_name("chrome.exe").await,
    ];

    for pid in target_processes.into_iter().flatten() {
        println!("🔍 Scanning PID {}...", pid);

        match scan_specific_process(&guard, pid).await {
            Ok(result) => {
                println!("   Result: {} (confidence: {:.2})",
                        result.status, result.risk_score);

                if !result.detections.is_empty() {
                    println!("   ⚠️  Detections:");
                    for detection in &result.detections {
                        println!("      - {}: {:.2} confidence",
                                detection.technique, detection.confidence);
                    }
                }
            },
            Err(e) => println!("   ❌ Scan failed: {}", e),
        }
    }

    println!("✅ Targeted scanning complete\n");
    Ok(())
}

async fn custom_detection() -> anyhow::Result<()> {
    println!("3. Custom Detection Logic");
    println!("------------------------");

    let guard = ProcessGuard::new().await?;
    guard.start().await?;

    println!("🔬 Running custom detection patterns...");

    let suspicious_processes = find_suspicious_processes(&guard).await?;

    if suspicious_processes.is_empty() {
        println!("   ✅ No suspicious processes found");
    } else {
        println!("   ⚠️  Found {} suspicious processes:", suspicious_processes.len());

        for (pid, info) in suspicious_processes {
            println!("      PID {}: {} (parent: {})",
                    pid, info.name, info.parent_pid);

            if should_terminate_process(&info).await {
                println!("         🎯 Terminating malicious process...");
                terminate_process(pid).await?;
            }
        }
    }

    println!("✅ Custom detection complete\n");
    Ok(())
}

async fn api_integration() -> anyhow::Result<()> {
    println!("4. API Integration Example");
    println!("-------------------------");

    let client = reqwest::Client::new();
    let base_url = "http://127.0.0.1:8080/api";

    println!("🌐 Connecting to Process Guard API...");

    let health = client
        .get(&format!("{}/health", base_url))
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;

    println!("   API Status: {}", health["status"]);
    println!("   Version: {}", health["version"]);

    let stats = client
        .get(&format!("{}/stats", base_url))
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;

    println!("   Total Detections: {}", stats["totals"]["detections"]);
    println!("   Detection Latency: {}ms",
            stats["performance"]["detection_latency_ms"]);

    let processes = client
        .get(&format!("{}/processes?suspicious=true", base_url))
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;

    println!("   Suspicious Processes: {}", processes["suspicious"]);

    println!("✅ API integration complete\n");
    Ok(())
}

async fn get_process_by_name(name: &str) -> Option<u32> {
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
                    let process_name = String::from_utf16_lossy(
                        &process_entry.szExeFile[..process_entry.szExeFile.iter()
                            .position(|&x| x == 0)
                            .unwrap_or(process_entry.szExeFile.len())]
                    );

                    if process_name.eq_ignore_ascii_case(name) {
                        let _ = CloseHandle(snapshot);
                        return Some(process_entry.th32ProcessID);
                    }

                    if !Process32NextW(snapshot, &mut process_entry).is_ok() {
                        break;
                    }
                }
            }

            let _ = CloseHandle(snapshot);
        }
    }
    None
}

#[derive(serde::Deserialize)]
struct ScanResult {
    pid: u32,
    status: String,
    risk_score: f32,
    detections: Vec<DetectionInfo>,
}

#[derive(serde::Deserialize)]
struct DetectionInfo {
    technique: String,
    confidence: f32,
    details: String,
}

async fn scan_specific_process(guard: &ProcessGuard, pid: u32) -> anyhow::Result<ScanResult> {
    let client = reqwest::Client::new();
    let response = client
        .post(&format!("http://127.0.0.1:8080/api/scan/{}", pid))
        .send()
        .await?
        .json::<ScanResult>()
        .await?;

    Ok(response)
}

async fn find_suspicious_processes(guard: &ProcessGuard) -> anyhow::Result<Vec<(u32, ProcessInfo)>> {
    let mut suspicious = Vec::new();

    for entry in guard.processes.iter() {
        let (pid, info) = entry.pair();

        if is_suspicious_process(info).await {
            suspicious.push((*pid, info.clone()));
        }
    }

    Ok(suspicious)
}

async fn is_suspicious_process(info: &ProcessInfo) -> bool {
    let suspicious_patterns = vec![
        "cmd.exe",
        "powershell.exe",
        "wmic.exe",
        "rundll32.exe",
        "regsvr32.exe",
    ];

    suspicious_patterns.iter().any(|&pattern| {
        info.name.to_lowercase().contains(pattern)
    })
}

async fn should_terminate_process(info: &ProcessInfo) -> bool {
    let dangerous_processes = vec![
        "mimikatz.exe",
        "procdump.exe",
        "psinject.exe",
        "malware.exe",
    ];

    dangerous_processes.iter().any(|&pattern| {
        info.name.to_lowercase().contains(pattern)
    })
}

async fn terminate_process(pid: u32) -> anyhow::Result<()> {
    let client = reqwest::Client::new();

    let response = client
        .delete(&format!("http://127.0.0.1:8080/api/processes/{}", pid))
        .send()
        .await?;

    if response.status().is_success() {
        println!("      ✅ Process {} terminated", pid);
    } else {
        println!("      ❌ Failed to terminate process {}", pid);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_process_enumeration() {
        let result = get_process_by_name("explorer.exe").await;
        assert!(result.is_some(), "explorer.exe should be running");
    }

    #[tokio::test]
    async fn test_process_guard_creation() {
        let guard = ProcessGuard::new().await;
        assert!(guard.is_ok(), "ProcessGuard should initialize successfully");
    }

    #[test]
    fn test_suspicious_pattern_detection() {
        tokio_test::block_on(async {
            let info = ProcessInfo {
                pid: 1234,
                name: "cmd.exe".to_string(),
                parent_pid: 1000,
                create_time: 0,
                image_base: 0,
                entry_point: 0,
            };

            assert!(is_suspicious_process(&info).await);
        });
    }

    #[test]
    fn test_termination_decision() {
        tokio_test::block_on(async {
            let malware = ProcessInfo {
                pid: 5678,
                name: "mimikatz.exe".to_string(),
                parent_pid: 1234,
                create_time: 0,
                image_base: 0,
                entry_point: 0,
            };

            assert!(should_terminate_process(&malware).await);

            let legitimate = ProcessInfo {
                pid: 1000,
                name: "notepad.exe".to_string(),
                parent_pid: 800,
                create_time: 0,
                image_base: 0,
                entry_point: 0,
            };

            assert!(!should_terminate_process(&legitimate).await);
        });
    }
}