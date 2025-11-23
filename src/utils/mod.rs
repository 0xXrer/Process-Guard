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
