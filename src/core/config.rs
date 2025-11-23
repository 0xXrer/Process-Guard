use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use thiserror::Error;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config {
    pub monitoring: MonitoringConfig,
    pub detection: DetectionConfig,
    pub logging: LoggingConfig,
    pub performance: PerformanceConfig,
    pub api: ApiConfig,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MonitoringConfig {
    pub interval_ms: u64,
    pub enable_etw: bool,
    pub enable_ml: bool,
    pub enable_txf: bool,
    pub whitelist: Vec<String>,
    pub blacklist: Vec<String>,
    pub auto_kill: bool,
    pub quarantine_dir: Option<PathBuf>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DetectionConfig {
    pub confidence_threshold: f32,
    pub ml_threshold: f32,
    pub techniques: Vec<String>,
    pub custom_patterns: Vec<DetectionPattern>,
    pub false_positive_reduction: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DetectionPattern {
    pub name: String,
    pub pattern: String,
    pub confidence: f32,
    pub enabled: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LoggingConfig {
    pub level: String,
    pub file: Option<PathBuf>,
    pub max_size_mb: u64,
    pub max_files: u32,
    pub json_format: bool,
    pub syslog: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PerformanceConfig {
    pub max_memory_mb: u64,
    pub cpu_limit_percent: u8,
    pub thread_pool_size: Option<usize>,
    pub cache_size: usize,
    pub gc_interval_ms: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ApiConfig {
    pub enabled: bool,
    pub bind_address: String,
    pub port: u16,
    pub auth_token: Option<String>,
    pub rate_limit: u32,
    pub cors: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            monitoring: MonitoringConfig {
                interval_ms: 100,
                enable_etw: true,
                enable_ml: true,
                enable_txf: true,
                whitelist: vec![
                    "explorer.exe".to_string(),
                    "winlogon.exe".to_string(),
                    "dwm.exe".to_string(),
                ],
                blacklist: vec![],
                auto_kill: false,
                quarantine_dir: None,
            },
            detection: DetectionConfig {
                confidence_threshold: 0.8,
                ml_threshold: 0.9,
                techniques: vec![
                    "ProcessHollowing".to_string(),
                    "ThreadHijacking".to_string(),
                    "ProcessDoppelganging".to_string(),
                ],
                custom_patterns: vec![],
                false_positive_reduction: true,
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                file: None,
                max_size_mb: 100,
                max_files: 5,
                json_format: false,
                syslog: false,
            },
            performance: PerformanceConfig {
                max_memory_mb: 512,
                cpu_limit_percent: 80,
                thread_pool_size: None,
                cache_size: 10000,
                gc_interval_ms: 30000,
            },
            api: ApiConfig {
                enabled: true,
                bind_address: "127.0.0.1".to_string(),
                port: 8080,
                auth_token: None,
                rate_limit: 100,
                cors: false,
            },
        }
    }
}

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Configuration file not found: {0}")]
    NotFound(PathBuf),
    #[error("Invalid configuration: {0}")]
    Invalid(String),
    #[error("Permission denied: {0}")]
    PermissionDenied(PathBuf),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] toml::ser::Error),
    #[error("Deserialization error: {0}")]
    Deserialization(#[from] toml::de::Error),
}

impl Config {
    pub fn load(path: Option<PathBuf>) -> Result<Self, ConfigError> {
        let config_path = match path {
            Some(p) => p,
            None => Self::default_config_path()?,
        };

        if !config_path.exists() {
            let default_config = Self::default();
            default_config.save(&config_path)?;
            return Ok(default_config);
        }

        let content = std::fs::read_to_string(&config_path)
            .map_err(ConfigError::Io)?;

        let config: Config = toml::from_str(&content)
            .map_err(ConfigError::Deserialization)?;

        config.validate()?;
        Ok(config)
    }

    pub fn save(&self, path: &PathBuf) -> Result<(), ConfigError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(ConfigError::Io)?;
        }

        let content = toml::to_string_pretty(self)
            .map_err(ConfigError::Serialization)?;

        std::fs::write(path, content)
            .map_err(ConfigError::Io)?;

        Ok(())
    }

    fn default_config_path() -> Result<PathBuf, ConfigError> {
        let config_dir = dirs::config_dir()
            .ok_or_else(|| ConfigError::Invalid("Cannot find config directory".to_string()))?;

        Ok(config_dir.join("process-guard").join("config.toml"))
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.monitoring.interval_ms == 0 {
            return Err(ConfigError::Invalid("Monitoring interval cannot be zero".to_string()));
        }

        if self.detection.confidence_threshold < 0.0 || self.detection.confidence_threshold > 1.0 {
            return Err(ConfigError::Invalid("Confidence threshold must be between 0.0 and 1.0".to_string()));
        }

        if self.performance.max_memory_mb == 0 {
            return Err(ConfigError::Invalid("Max memory cannot be zero".to_string()));
        }

        if self.performance.cpu_limit_percent > 100 {
            return Err(ConfigError::Invalid("CPU limit cannot exceed 100%".to_string()));
        }

        if self.api.port == 0 {
            return Err(ConfigError::Invalid("API port cannot be zero".to_string()));
        }

        Ok(())
    }

    pub fn get(&self, key: &str) -> Option<String> {
        match key {
            "monitoring.interval_ms" => Some(self.monitoring.interval_ms.to_string()),
            "detection.confidence_threshold" => Some(self.detection.confidence_threshold.to_string()),
            "api.port" => Some(self.api.port.to_string()),
            "logging.level" => Some(self.logging.level.clone()),
            _ => None,
        }
    }

    pub fn set(&mut self, key: &str, value: &str) -> Result<(), ConfigError> {
        match key {
            "monitoring.interval_ms" => {
                self.monitoring.interval_ms = value.parse()
                    .map_err(|_| ConfigError::Invalid(format!("Invalid interval: {}", value)))?;
            },
            "detection.confidence_threshold" => {
                self.detection.confidence_threshold = value.parse()
                    .map_err(|_| ConfigError::Invalid(format!("Invalid confidence: {}", value)))?;
            },
            "api.port" => {
                self.api.port = value.parse()
                    .map_err(|_| ConfigError::Invalid(format!("Invalid port: {}", value)))?;
            },
            "logging.level" => {
                if !["trace", "debug", "info", "warn", "error"].contains(&value) {
                    return Err(ConfigError::Invalid(format!("Invalid log level: {}", value)));
                }
                self.logging.level = value.to_string();
            },
            _ => return Err(ConfigError::Invalid(format!("Unknown config key: {}", key))),
        }

        self.validate()?;
        Ok(())
    }
}
