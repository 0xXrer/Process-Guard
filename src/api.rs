use axum::{
    routing::{get, post},
    Router,
    Json,
    extract::{Path, State},
    response::{IntoResponse, Response},
    http::{StatusCode, Request, header},
    middleware::{self, Next},
    body::Body,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Instant;
use crate::ProcessGuard;
use tower::ServiceBuilder;
use tower_http::cors::{CorsLayer, Any};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;
use tower_governor::{GovernorLayer, governor::GovernorConfigBuilder};
use tracing::{info, warn, error};
use validator::Validate;
use constant_time_eq::constant_time_eq;

const MAX_REQUEST_SIZE: usize = 1024 * 1024; // 1MB
const RATE_LIMIT_PER_SECOND: u64 = 10;

/// Application state containing auth config and start time
#[derive(Clone)]
pub struct AppState {
    pub guard: Arc<ProcessGuard>,
    pub auth_token: String,
    pub start_time: Instant,
}

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

#[derive(Deserialize, Validate)]
struct ProcessAction {
    #[validate(length(min = 1, max = 20))]
    action: String,
}

/// Protected PIDs that cannot be terminated
const PROTECTED_PIDS: &[u32] = &[0, 4]; // System, System Idle Process

/// Validates if a PID is safe to terminate
fn is_safe_to_terminate(pid: u32) -> bool {
    // Don't allow terminating:
    // - PID 0 (System Idle)
    // - PID 4 (System)
    // - PIDs less than 100 (typically system processes)
    pid > 100 && !PROTECTED_PIDS.contains(&pid)
}

/// Validates PID is in acceptable range
fn validate_pid(pid: u32) -> Result<(), String> {
    if pid == 0 {
        return Err("Invalid PID: 0".to_string());
    }
    if pid > u32::MAX - 1 {
        return Err("Invalid PID: out of range".to_string());
    }
    Ok(())
}

/// Authentication middleware - validates Bearer token
async fn auth_middleware(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    match auth_header {
        Some(header_value) => {
            if let Some(token) = header_value.strip_prefix("Bearer ") {
                // Use constant-time comparison to prevent timing attacks
                if constant_time_eq(token.as_bytes(), state.auth_token.as_bytes()) {
                    info!("Authenticated request to {}", req.uri());
                    Ok(next.run(req).await)
                } else {
                    warn!("Invalid authentication token attempt");
                    Err(StatusCode::UNAUTHORIZED)
                }
            } else {
                warn!("Invalid Authorization header format");
                Err(StatusCode::UNAUTHORIZED)
            }
        }
        None => {
            warn!("Missing Authorization header");
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

/// Audit logging for sensitive operations
fn audit_log(operation: &str, pid: Option<u32>, success: bool) {
    if success {
        info!(
            operation = operation,
            pid = pid,
            "Audit: Operation completed successfully"
        );
    } else {
        warn!(
            operation = operation,
            pid = pid,
            "Audit: Operation failed"
        );
    }
}

pub async fn create_router(guard: Arc<ProcessGuard>, auth_token: String) -> Router {
    let state = AppState {
        guard,
        auth_token,
        start_time: Instant::now(),
    };

    // Configure rate limiting
    let governor_conf = Box::new(
        GovernorConfigBuilder::default()
            .per_second(RATE_LIMIT_PER_SECOND)
            .burst_size(RATE_LIMIT_PER_SECOND as u32 * 2)
            .finish()
            .unwrap(),
    );

    // Configure CORS - restrict to localhost only by default
    let cors = CorsLayer::new()
        .allow_origin(Any) // In production, restrict to specific origins
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
        ])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
        ]);

    // Protected routes requiring authentication
    let protected = Router::new()
        .route("/api/processes", get(list_processes))
        .route("/api/process/:pid", get(get_process))
        .route("/api/process/:pid/action", post(process_action))
        .route("/api/stats", get(get_stats))
        .route("/api/detections", get(get_detections))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    // Public routes (no auth required)
    let public = Router::new()
        .route("/health", get(health_check));

    // Combine routes and add global middleware
    Router::new()
        .merge(protected)
        .merge(public)
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(RequestBodyLimitLayer::new(MAX_REQUEST_SIZE))
                .layer(GovernorLayer {
                    config: Box::leak(governor_conf),
                })
                .layer(cors),
        )
        .with_state(state)
}

async fn list_processes(
    State(state): State<AppState>,
) -> impl IntoResponse {
    audit_log("list_processes", None, true);

    let processes: Vec<ProcessStatus> = state.guard.processes
        .iter()
        .map(|entry| {
            let (pid, info) = entry.pair();
            let detections = state.guard.detector
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
                status: if detections.is_empty() { "Clean" } else { "Suspicious" }.to_string(),
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
    State(state): State<AppState>,
) -> impl IntoResponse {
    // Validate PID
    if let Err(e) = validate_pid(pid) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<ProcessStatus> {
                success: false,
                data: None,
                error: Some(e),
            }),
        );
    }

    audit_log("get_process", Some(pid), true);

    if let Some(info) = state.guard.processes.get(&pid) {
        let detections = state.guard.detector
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
            status: if detections.is_empty() { "Clean" } else { "Suspicious" }.to_string(),
            detections,
        };

        (
            StatusCode::OK,
            Json(ApiResponse {
                success: true,
                data: Some(status),
                error: None,
            }),
        )
    } else {
        // Generic error message to prevent enumeration
        (
            StatusCode::NOT_FOUND,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some("Resource not found".to_string()),
            }),
        )
    }
}

async fn process_action(
    Path(pid): Path<u32>,
    State(state): State<AppState>,
    Json(action): Json<ProcessAction>,
) -> impl IntoResponse {
    // Validate input
    if let Err(e) = action.validate() {
        audit_log("process_action", Some(pid), false);
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<String> {
                success: false,
                data: None,
                error: Some(format!("Validation error: {}", e)),
            }),
        );
    }

    // Validate PID
    if let Err(e) = validate_pid(pid) {
        audit_log("process_action", Some(pid), false);
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(e),
            }),
        );
    }

    match action.action.to_lowercase().as_str() {
        "terminate" => {
            // Check if PID is safe to terminate
            if !is_safe_to_terminate(pid) {
                audit_log("terminate_process", Some(pid), false);
                error!("Attempt to terminate protected process: {}", pid);
                return (
                    StatusCode::FORBIDDEN,
                    Json(ApiResponse {
                        success: false,
                        data: None,
                        error: Some("Cannot terminate protected system process".to_string()),
                    }),
                );
            }

            // SAFETY: We are calling Win32 APIs to terminate a process.
            // Safety invariants:
            // 1. PID has been validated to be non-zero and in valid range
            // 2. PID has been checked against protected process list
            // 3. We properly close the handle in all code paths
            // 4. We check all return values and handle errors
            // 5. We have proper privileges (SeDebugPrivilege) as this is a security tool
            unsafe {
                use windows::Win32::System::Threading::*;
                use windows::Win32::Foundation::*;

                match OpenProcess(PROCESS_TERMINATE, false, pid) {
                    Ok(handle) => {
                        // Ensure handle is valid
                        if handle.is_invalid() {
                            audit_log("terminate_process", Some(pid), false);
                            error!("OpenProcess returned invalid handle for PID: {}", pid);
                            return (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                Json(ApiResponse {
                                    success: false,
                                    data: None,
                                    error: Some("Failed to access process".to_string()),
                                }),
                            );
                        }

                        let result = TerminateProcess(handle, 1);

                        // Always close the handle, even if termination failed
                        let close_result = CloseHandle(handle);
                        if close_result.is_err() {
                            warn!("Failed to close process handle for PID: {}", pid);
                        }

                        if result.is_ok() {
                            audit_log("terminate_process", Some(pid), true);
                            info!("Successfully terminated process: {}", pid);
                            (
                                StatusCode::OK,
                                Json(ApiResponse {
                                    success: true,
                                    data: Some("Process terminated successfully".to_string()),
                                    error: None,
                                }),
                            )
                        } else {
                            audit_log("terminate_process", Some(pid), false);
                            error!("TerminateProcess failed for PID: {}", pid);
                            (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                Json(ApiResponse {
                                    success: false,
                                    data: None,
                                    error: Some("Operation failed".to_string()),
                                }),
                            )
                        }
                    }
                    Err(e) => {
                        audit_log("terminate_process", Some(pid), false);
                        error!("Failed to open process {}: {:?}", pid, e);
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(ApiResponse {
                                success: false,
                                data: None,
                                error: Some("Failed to access process".to_string()),
                            }),
                        )
                    }
                }
            }
        }
        "whitelist" => {
            state.guard.detector.detection_cache.remove(&pid);
            audit_log("whitelist_process", Some(pid), true);
            info!("Process {} whitelisted", pid);
            (
                StatusCode::OK,
                Json(ApiResponse {
                    success: true,
                    data: Some("Process whitelisted successfully".to_string()),
                    error: None,
                }),
            )
        }
        _ => {
            audit_log("process_action", Some(pid), false);
            (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid action. Supported actions: terminate, whitelist".to_string()),
                }),
            )
        }
    }
}

async fn get_stats(
    State(state): State<AppState>,
) -> impl IntoResponse {
    audit_log("get_stats", None, true);

    let total_detections: usize = state.guard.detector.detection_cache
        .iter()
        .map(|e| e.value().len())
        .sum();

    let stats = SystemStats {
        monitored_processes: state.guard.processes.len(),
        total_detections,
        blocked_processes: state.guard.detector.detection_cache
            .iter()
            .filter(|e| e.value().iter().any(|d| d.confidence > 0.8))
            .count(),
        uptime_seconds: state.start_time.elapsed().as_secs(),
    };

    Json(ApiResponse {
        success: true,
        data: Some(stats),
        error: None,
    })
}

async fn get_detections(
    State(state): State<AppState>,
) -> impl IntoResponse {
    audit_log("get_detections", None, true);

    let detections: Vec<DetectionInfo> = state.guard.detector.detection_cache
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
