pub mod core;
pub mod detection;
pub mod monitoring;
pub mod platform;
pub mod interface;
pub mod utils;

pub use core::{ProcessGuard, ProcessInfo, InjectionType, Config};
pub use utils::{GuardError, Result};