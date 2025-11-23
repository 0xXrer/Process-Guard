use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "process-guard")]
#[command(about = "Real-time process injection detection and prevention")]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    #[arg(short, long, help = "Configuration file path")]
    pub config: Option<PathBuf>,

    #[arg(short, long, help = "Enable verbose logging")]
    pub verbose: bool,

    #[arg(short, long, help = "Log file path")]
    pub log_file: Option<PathBuf>,

    #[arg(long, help = "Disable colors in output")]
    pub no_color: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    #[command(about = "Start monitoring processes")]
    Monitor {
        #[arg(short, long, help = "Run as daemon")]
        daemon: bool,

        #[arg(short, long, help = "PID file for daemon mode")]
        pid_file: Option<PathBuf>,

        #[arg(short, long, help = "Monitoring interval in milliseconds", default_value = "100")]
        interval: u64,

        #[arg(long, help = "Enable ETW monitoring")]
        etw: bool,

        #[arg(long, help = "Enable ML anomaly detection")]
        ml: bool,

        #[arg(long, help = "Enable TxF Process Doppelgänging detection")]
        txf: bool,

        #[arg(long, help = "Processes to whitelist (comma-separated)")]
        whitelist: Option<String>,

        #[arg(long, help = "Processes to blacklist (comma-separated)")]
        blacklist: Option<String>,
    },

    #[command(about = "Scan specific process")]
    Scan {
        #[arg(help = "Process ID to scan")]
        pid: u32,

        #[arg(short, long, help = "Output format")]
        format: Option<OutputFormat>,

        #[arg(long, help = "Save scan results to file")]
        output: Option<PathBuf>,

        #[arg(long, help = "Scan techniques to use")]
        techniques: Option<Vec<ScanTechnique>>,
    },

    #[command(about = "List running processes")]
    List {
        #[arg(short, long, help = "Show suspicious processes only")]
        suspicious: bool,

        #[arg(short, long, help = "Show detailed information")]
        detailed: bool,

        #[arg(short, long, help = "Filter by process name")]
        filter: Option<String>,
    },

    #[command(about = "Show detection statistics")]
    Stats {
        #[arg(short, long, help = "Show real-time stats")]
        realtime: bool,

        #[arg(short, long, help = "Time range in hours", default_value = "24")]
        hours: u32,

        #[arg(short, long, help = "Export stats to file")]
        export: Option<PathBuf>,
    },

    #[command(about = "Manage configuration")]
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },

    #[command(about = "Kill malicious process")]
    Kill {
        #[arg(help = "Process ID to terminate")]
        pid: u32,

        #[arg(short, long, help = "Force kill without confirmation")]
        force: bool,
    },

    #[command(about = "Export detection rules")]
    Export {
        #[arg(help = "Export format")]
        format: ExportFormat,

        #[arg(short, long, help = "Output file path")]
        output: PathBuf,

        #[arg(long, help = "Include detection statistics")]
        stats: bool,
    },

    #[command(about = "Run benchmarks")]
    Benchmark {
        #[arg(short, long, help = "Benchmark type")]
        bench_type: BenchmarkType,

        #[arg(short, long, help = "Number of iterations", default_value = "1000")]
        iterations: u32,

        #[arg(short, long, help = "Save results to file")]
        output: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
pub enum ConfigAction {
    #[command(about = "Show current configuration")]
    Show,

    #[command(about = "Set configuration value")]
    Set {
        #[arg(help = "Configuration key")]
        key: String,

        #[arg(help = "Configuration value")]
        value: String,
    },

    #[command(about = "Reset to default configuration")]
    Reset,

    #[command(about = "Validate configuration file")]
    Validate {
        #[arg(help = "Configuration file to validate")]
        file: Option<PathBuf>,
    },
}

#[derive(ValueEnum, Clone, Debug)]
pub enum OutputFormat {
    Json,
    Yaml,
    Table,
    Plain,
}

#[derive(ValueEnum, Clone, Debug)]
pub enum ScanTechnique {
    ProcessHollowing,
    ThreadHijacking,
    ApcQueue,
    ReflectiveDll,
    ProcessDoppelganging,
    All,
}

#[derive(ValueEnum, Clone, Debug)]
pub enum ExportFormat {
    Json,
    Yara,
    Sigma,
    Csv,
}

#[derive(ValueEnum, Clone, Debug)]
pub enum BenchmarkType {
    Detection,
    Memory,
    Performance,
    Txf,
    All,
}
