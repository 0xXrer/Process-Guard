use axum::{
    routing::{get, post},
    Router,
    Json,
    extract::{Path, State},
    response::IntoResponse,
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use crate::ProcessGuard;

#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
}

#[derive(Serialize)]
struct ProcessStatus {
    pid: u32,
    name: String,
    status: String,
    detections: Vec<DetectionInfo>,
}

#[derive(Serialize)]
struct DetectionInfo {
    injection_type: String,
    confidence: f32,
    timestamp: u64,
    details: String,
}

#[derive(Serialize)]
struct SystemStats {
    monitored_processes: usize,
    total_detections: usize,
    blocked_processes: usize,
    uptime_seconds: u64,
}

#[derive(Deserialize)]
struct ProcessAction {
    action: String,
}

pub async fn create_router(guard: Arc<ProcessGuard>) -> Router {
    Router::new()
        .route("/api/processes", get(list_processes))
        .route("/api/process/:pid", get(get_process))
        .route("/api/process/:pid/action", post(process_action))
        .route("/api/stats", get(get_stats))
        .route("/api/detections", get(get_detections))
        .route("/health", get(health_check))
        .with_state(guard)
}

async fn list_processes(
    State(guard): State<Arc<ProcessGuard>>,
) -> impl IntoResponse {
    let processes: Vec<ProcessStatus> = guard.processes
        .iter()
        .map(|entry| {
            let (pid, info) = entry.pair();
            let detections = guard.detector
                .detection_cache
                .get(pid)
                .map(|d| d.iter().map(|det| DetectionInfo {
                    injection_type: format!("{:?}", det.injection_type),
                    confidence: det.confidence,
                    timestamp: det.timestamp,
                    details: det.details.clone(),
                }).collect())
                .unwrap_or_default();
            
            ProcessStatus {
                pid: *pid,
                name: info.name.clone(),
                status: if detections.is_empty() { "Clean" } else { "Infected" }.to_string(),
                detections,
            }
        })
        .collect();

    Json(ApiResponse {
        success: true,
        data: Some(processes),
        error: None,
    })
}

async fn get_process(
    Path(pid): Path<u32>,
    State(guard): State<Arc<ProcessGuard>>,
) -> impl IntoResponse {
    if let Some(info) = guard.processes.get(&pid) {
        let detections = guard.detector
            .detection_cache
            .get(&pid)
            .map(|d| d.iter().map(|det| DetectionInfo {
                injection_type: format!("{:?}", det.injection_type),
                confidence: det.confidence,
                timestamp: det.timestamp,
                details: det.details.clone(),
            }).collect())
            .unwrap_or_default();
        
        let status = ProcessStatus {
            pid,
            name: info.name.clone(),
            status: if detections.is_empty() { "Clean" } else { "Infected" }.to_string(),
            detections,
        };
        
        Json(ApiResponse {
            success: true,
            data: Some(status),
            error: None,
        })
    } else {
        Json(ApiResponse {
            success: false,
            data: None,
            error: Some("Process not found".to_string()),
        })
    }
}

async fn process_action(
    Path(pid): Path<u32>,
    State(guard): State<Arc<ProcessGuard>>,
    Json(action): Json<ProcessAction>,
) -> impl IntoResponse {
    match action.action.as_str() {
        "terminate" => {
            unsafe {
                use windows::Win32::System::Threading::*;
                if let Ok(handle) = OpenProcess(PROCESS_TERMINATE, false, pid) {
                    let _ = TerminateProcess(handle, 1);
                    let _ = CloseHandle(handle);
                    
                    Json(ApiResponse {
                        success: true,
                        data: Some("Process terminated".to_string()),
                        error: None,
                    })
                } else {
                    Json(ApiResponse {
                        success: false,
                        data: None,
                        error: Some("Failed to terminate process".to_string()),
                    })
                }
            }
        },
        "whitelist" => {
            guard.detector.detection_cache.remove(&pid);
            Json(ApiResponse {
                success: true,
                data: Some("Process whitelisted".to_string()),
                error: None,
            })
        },
        _ => {
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some("Invalid action".to_string()),
            })
        }
    }
}

async fn get_stats(
    State(guard): State<Arc<ProcessGuard>>,
) -> impl IntoResponse {
    let total_detections: usize = guard.detector.detection_cache
        .iter()
        .map(|e| e.value().len())
        .sum();
    
    let stats = SystemStats {
        monitored_processes: guard.processes.len(),
        total_detections,
        blocked_processes: guard.detector.detection_cache
            .iter()
            .filter(|e| e.value().iter().any(|d| d.confidence > 0.8))
            .count(),
        uptime_seconds: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };
    
    Json(ApiResponse {
        success: true,
        data: Some(stats),
        error: None,
    })
}

async fn get_detections(
    State(guard): State<Arc<ProcessGuard>>,
) -> impl IntoResponse {
    let detections: Vec<DetectionInfo> = guard.detector.detection_cache
        .iter()
        .flat_map(|e| e.value().iter().map(|d| DetectionInfo {
            injection_type: format!("{:?}", d.injection_type),
            confidence: d.confidence,
            timestamp: d.timestamp,
            details: d.details.clone(),
        }))
        .collect();
    
    Json(ApiResponse {
        success: true,
        data: Some(detections),
        error: None,
    })
}

async fn health_check() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}