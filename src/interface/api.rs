use axum::{
    routing::{get, post},
    Router,
    Json,
    extract::{Path, State},
    response::IntoResponse,
    http::{StatusCode, Request, header},
    middleware::{self, Next},
    body::Body,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Instant;
use crate::core::ProcessGuard;
use tower::ServiceBuilder;
use tower_http::cors::{CorsLayer, Any};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;
use tower_governor::{
    governor::GovernorConfigBuilder,
    GovernorLayer,
};
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use sha2::{Sha256, Digest};
use parking_lot::RwLock;

// ============================================================================
// SECURITY CONSTANTS
// ============================================================================

/// Protected system processes that cannot be terminated
const PROTECTED_PIDS: &[u32] = &[0, 4]; // System Idle Process, System

/// Maximum request body size (1 MB)
const MAX_REQUEST_SIZE: usize = 1_024_* 1_024;

/// Rate limit: 100 requests per minute per IP
const RATE_LIMIT_PER_MINUTE: u64 = 100;

/// Maximum PID value on Windows
const MAX_PID: u32 = 4_294_967_295;

// ============================================================================
// DATA STRUCTURES
// ============================================================================

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

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
    iat: usize,
}

/// Shared application state
pub struct AppState {
    pub guard: Arc<ProcessGuard>,
    pub start_time: Instant,
    pub api_keys: Arc<RwLock<Vec<String>>>,
}

// ============================================================================
// AUDIT LOGGING
// ============================================================================

/// Audit log entry for security events
#[derive(Debug, Serialize)]
struct AuditLog {
    timestamp: u64,
    action: String,
    user: String,
    target: Option<String>,
    success: bool,
    error: Option<String>,
}

impl AuditLog {
    fn new(action: &str, user: &str, target: Option<&str>, success: bool, error: Option<&str>) -> Self {
        Self {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            action: action.to_string(),
            user: user.to_string(),
            target: target.map(|s| s.to_string()),
            success,
            error: error.map(|s| s.to_string()),
        }
    }

    fn log(&self) {
        tracing::info!(
            target: "process_guard::audit",
            timestamp = %self.timestamp,
            action = %self.action,
            user = %self.user,
            target = ?self.target,
            success = %self.success,
            error = ?self.error,
            "AUDIT_LOG"
        );
    }
}

// ============================================================================
// AUTHENTICATION MIDDLEWARE
// ============================================================================

/// Authentication middleware - validates Bearer tokens
async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    mut req: Request<Body>,
    next: Next,
) -> Result<impl IntoResponse, StatusCode> {
    // Allow health check without authentication
    if req.uri().path() == "/health" {
        return Ok(next.run(req).await);
    }

    let auth_header = req.headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    let user = match auth_header {
        Some(auth) if auth.starts_with("Bearer ") => {
            let token = &auth[7..];

            // Validate token (checking against configured API keys)
            let api_keys = state.api_keys.read();
            let token_hash = format!("{:x}", Sha256::digest(token.as_bytes()));

            if api_keys.iter().any(|key| key == &token_hash) {
                "api_user".to_string()
            } else {
                // Try JWT validation as fallback
                match validate_jwt(token) {
                    Ok(claims) => claims.sub,
                    Err(_) => {
                        AuditLog::new("auth_failed", "unknown", None, false, Some("Invalid token")).log();
                        return Err(StatusCode::UNAUTHORIZED);
                    }
                }
            }
        },
        _ => {
            AuditLog::new("auth_failed", "unknown", None, false, Some("Missing or invalid Authorization header")).log();
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    // Store user in request extensions for later use
    req.extensions_mut().insert(user);

    Ok(next.run(req).await)
}

/// Validate JWT token
fn validate_jwt(token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    // In production, load this from a secure configuration
    let secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| "your-secret-key".to_string());

    let validation = Validation::new(Algorithm::HS256);
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )?;

    Ok(token_data.claims)
}

// ============================================================================
// INPUT VALIDATION
// ============================================================================

/// Validate PID input
fn validate_pid(pid: u32) -> Result<(), String> {
    if pid == 0 {
        return Err("Invalid PID: cannot be zero".to_string());
    }
    if pid > MAX_PID {
        return Err("Invalid PID: exceeds maximum value".to_string());
    }
    Ok(())
}

/// Check if process can be safely terminated
fn is_safe_to_terminate(pid: u32) -> bool {
    !PROTECTED_PIDS.contains(&pid)
}

/// Validate action string
fn validate_action(action: &str) -> Result<String, String> {
    let normalized = action.trim().to_lowercase();
    match normalized.as_str() {
        "terminate" | "whitelist" => Ok(normalized),
        _ => Err("Invalid action: must be 'terminate' or 'whitelist'".to_string()),
    }
}

// ============================================================================
// ROUTER CREATION
// ============================================================================

pub async fn create_router(guard: Arc<ProcessGuard>) -> Router {
    // Create shared state
    let state = Arc::new(AppState {
        guard,
        start_time: Instant::now(),
        api_keys: Arc::new(RwLock::new(load_api_keys())),
    });

    // Configure rate limiting
    let governor_conf = Box::new(
        GovernorConfigBuilder::default()
            .per_second(RATE_LIMIT_PER_MINUTE / 60)
            .burst_size(10)
            .finish()
            .unwrap()
    );

    // Configure CORS
    let cors = CorsLayer::new()
        .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
        .allow_origin(Any); // In production, restrict to specific origins

    Router::new()
        .route("/api/processes", get(list_processes))
        .route("/api/process/:pid", get(get_process))
        .route("/api/process/:pid/action", post(process_action))
        .route("/api/stats", get(get_stats))
        .route("/api/detections", get(get_detections))
        .route("/health", get(health_check))
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(RequestBodyLimitLayer::new(MAX_REQUEST_SIZE))
                .layer(cors)
                .layer(GovernorLayer {
                    config: Box::leak(governor_conf),
                })
                .layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
        )
        .with_state(state)
}

/// Load API keys from configuration
fn load_api_keys() -> Vec<String> {
    // In production, load from secure configuration file
    // For now, load from environment variable
    std::env::var("API_KEYS")
        .ok()
        .map(|keys| keys.split(',').map(|k| k.trim().to_string()).collect())
        .unwrap_or_default()
}

// ============================================================================
// API ENDPOINTS
// ============================================================================

async fn list_processes(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let user = "api_user"; // Would come from request extensions in real impl

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
                status: if detections.is_empty() { "Clean" } else { "Infected" }.to_string(),
                detections,
            }
        })
        .collect();

    AuditLog::new("list_processes", user, None, true, None).log();

    Json(ApiResponse {
        success: true,
        data: Some(processes),
        error: None,
    })
}

async fn get_process(
    Path(pid): Path<u32>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let user = "api_user"; // Would come from request extensions

    // Validate PID
    if let Err(e) = validate_pid(pid) {
        AuditLog::new("get_process", user, Some(&pid.to_string()), false, Some(&e)).log();
        return Json(ApiResponse {
            success: false,
            data: None,
            error: Some("Invalid request".to_string()), // Generic error message
        });
    }

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
            status: if detections.is_empty() { "Clean" } else { "Infected" }.to_string(),
            detections,
        };

        AuditLog::new("get_process", user, Some(&pid.to_string()), true, None).log();

        Json(ApiResponse {
            success: true,
            data: Some(status),
            error: None,
        })
    } else {
        AuditLog::new("get_process", user, Some(&pid.to_string()), false, Some("Not found")).log();
        Json(ApiResponse {
            success: false,
            data: None,
            error: Some("Resource not found".to_string()), // Generic error message
        })
    }
}

async fn process_action(
    Path(pid): Path<u32>,
    State(state): State<Arc<AppState>>,
    Json(action_req): Json<ProcessAction>,
) -> impl IntoResponse {
    let user = "api_user"; // Would come from request extensions

    // Validate PID
    if let Err(e) = validate_pid(pid) {
        AuditLog::new("process_action", user, Some(&pid.to_string()), false, Some(&e)).log();
        return Json(ApiResponse {
            success: false,
            data: None,
            error: Some("Invalid request".to_string()),
        });
    }

    // Validate and normalize action
    let action = match validate_action(&action_req.action) {
        Ok(a) => a,
        Err(e) => {
            AuditLog::new("process_action", user, Some(&pid.to_string()), false, Some(&e)).log();
            return Json(ApiResponse {
                success: false,
                data: None,
                error: Some("Invalid request".to_string()),
            });
        }
    };

    match action.as_str() {
        "terminate" => {
            // Check if process can be terminated
            if !is_safe_to_terminate(pid) {
                AuditLog::new("terminate_process", user, Some(&pid.to_string()), false,
                    Some("Attempt to terminate protected system process")).log();
                return Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Operation not permitted".to_string()),
                });
            }

            // SAFETY: We're calling Win32 APIs with validated input.
            // - pid is validated to be non-zero and not a protected process
            // - We properly close the handle even on error
            // - We check the return value of TerminateProcess
            // - OpenProcess may fail if we don't have sufficient privileges or if the process doesn't exist
            // - TerminateProcess may fail if the process has already exited
            unsafe {
                use windows::Win32::System::Threading::*;
                use windows::Win32::Foundation::CloseHandle;

                // Validate PID one more time before unsafe operation
                if pid == 0 || PROTECTED_PIDS.contains(&pid) {
                    AuditLog::new("terminate_process", user, Some(&pid.to_string()), false,
                        Some("Protected process")).log();
                    return Json(ApiResponse {
                        success: false,
                        data: None,
                        error: Some("Operation not permitted".to_string()),
                    });
                }

                match OpenProcess(PROCESS_TERMINATE, false, pid) {
                    Ok(handle) => {
                        let result = TerminateProcess(handle, 1);
                        // Always close handle, even if terminate failed
                        let _ = CloseHandle(handle);

                        if result.is_ok() {
                            AuditLog::new("terminate_process", user, Some(&pid.to_string()), true, None).log();
                            Json(ApiResponse {
                                success: true,
                                data: Some("Operation completed".to_string()),
                                error: None,
                            })
                        } else {
                            AuditLog::new("terminate_process", user, Some(&pid.to_string()), false,
                                Some("Termination failed")).log();
                            Json(ApiResponse {
                                success: false,
                                data: None,
                                error: Some("Operation failed".to_string()),
                            })
                        }
                    },
                    Err(_) => {
                        AuditLog::new("terminate_process", user, Some(&pid.to_string()), false,
                            Some("Failed to open process handle")).log();
                        Json(ApiResponse {
                            success: false,
                            data: None,
                            error: Some("Operation failed".to_string()),
                        })
                    }
                }
            }
        },
        "whitelist" => {
            state.guard.detector.detection_cache.remove(&pid);
            AuditLog::new("whitelist_process", user, Some(&pid.to_string()), true, None).log();
            Json(ApiResponse {
                success: true,
                data: Some("Operation completed".to_string()),
                error: None,
            })
        },
        _ => {
            // This should never happen due to validation, but handle it anyway
            AuditLog::new("process_action", user, Some(&pid.to_string()), false,
                Some("Invalid action")).log();
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some("Invalid request".to_string()),
            })
        }
    }
}

async fn get_stats(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let user = "api_user";

    let total_detections: usize = state.guard.detector.detection_cache
        .iter()
        .map(|e| e.value().len())
        .sum();

    // Fixed: Use actual start time instead of UNIX_EPOCH
    let uptime = state.start_time.elapsed().as_secs();

    let stats = SystemStats {
        monitored_processes: state.guard.processes.len(),
        total_detections,
        blocked_processes: state.guard.detector.detection_cache
            .iter()
            .filter(|e| e.value().iter().any(|d| d.confidence > 0.8))
            .count(),
        uptime_seconds: uptime,
    };

    AuditLog::new("get_stats", user, None, true, None).log();

    Json(ApiResponse {
        success: true,
        data: Some(stats),
        error: None,
    })
}

async fn get_detections(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let user = "api_user";

    let detections: Vec<DetectionInfo> = state.guard.detector.detection_cache
        .iter()
        .flat_map(|e| e.value().iter().map(|d| DetectionInfo {
            injection_type: format!("{:?}", d.injection_type),
            confidence: d.confidence,
            timestamp: d.timestamp,
            details: d.details.clone(),
        }))
        .collect();

    AuditLog::new("get_detections", user, None, true, None).log();

    Json(ApiResponse {
        success: true,
        data: Some(detections),
        error: None,
    })
}

async fn health_check() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}
