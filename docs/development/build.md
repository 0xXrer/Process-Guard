# Build Guide

Complete guide for building Process Guard from source, including development setup and distribution builds.

## 📋 Prerequisites

### System Requirements
- **OS**: Windows 10 (1809+) or Windows Server 2019+
- **CPU**: x64 processor (ARM64 support planned)
- **RAM**: 8GB+ recommended for development
- **Storage**: 10GB+ free space (for toolchain and dependencies)

### Required Tools

#### Rust Toolchain
```powershell
# Install Rust via rustup
Invoke-WebRequest -Uri "https://win.rustup.rs/x86_64" -OutFile "rustup-init.exe"
.\rustup-init.exe -y
refreshenv

# Verify installation
rustc --version
cargo --version

# Install required components
rustup component add clippy rustfmt
rustup target add x86_64-pc-windows-msvc
```

#### Visual Studio Build Tools
```powershell
# Download and install VS Build Tools 2022
# Minimum components needed:
# - MSVC v143 compiler toolset
# - Windows 10/11 SDK (latest)
# - CMake tools for Visual Studio (optional)

# Verify installation
where cl
```

#### Windows SDK
```powershell
# Download latest Windows SDK from:
# https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/

# Or install via chocolatey
choco install windows-sdk-10-version-2004-all
```

### Development Tools (Recommended)

#### Code Analysis
```powershell
cargo install cargo-clippy
cargo install cargo-audit
cargo install cargo-outdated
cargo install cargo-tree
```

#### Testing & Coverage
```powershell
cargo install cargo-tarpaulin  # Code coverage
cargo install cargo-nextest    # Faster test runner
cargo install cargo-fuzz       # Fuzzing support
```

#### Documentation
```powershell
cargo install cargo-doc
cargo install mdbook           # For documentation
```

#### Performance Analysis
```powershell
cargo install cargo-flamegraph # Profiling
cargo install cargo-watch      # File watching
cargo install cargo-benchcmp   # Benchmark comparison
```

## 🚀 Quick Build

### Clone Repository
```powershell
# Clone main repository
git clone https://github.com/xrer/process-guard.git
cd process-guard

# Or clone your fork for development
git clone https://github.com/YOUR_USERNAME/process-guard.git
cd process-guard
git remote add upstream https://github.com/xrer/process-guard.git
```

### Development Build
```powershell
# Debug build (fast compilation, larger binary, debug symbols)
cargo build

# Check if it compiled successfully
.\target\debug\process-guard.exe --version

# Run basic tests
cargo test
```

### Release Build
```powershell
# Optimized build (slower compilation, smaller binary, optimized)
cargo build --release

# Binary location
.\target\release\process-guard.exe --version

# Run full test suite
cargo test --release --all-features
```

## ⚙️ Build Configuration

### Cargo.toml Features
```toml
[features]
default = ["etw", "ml", "api"]

# Core features
etw = ["windows-etw"]              # ETW integration
ml = ["candle-core", "tokenizers"] # Machine learning
api = ["warp", "tokio"]            # REST API server

# Optional features
driver = ["wdk"]                   # Kernel driver support
crypto = ["ring", "rustls"]        # Cryptographic features
syslog = ["syslog"]               # Syslog integration

# Development features
debug-symbols = []                 # Include debug symbols in release
profiling = ["profiling-procmacro"] # Enable profiling markers
```

### Build with Specific Features
```powershell
# Minimal build (core detection only)
cargo build --no-default-features --features "etw"

# Full featured build
cargo build --all-features

# Custom feature combination
cargo build --features "etw,api,crypto"

# Release with debug symbols
cargo build --release --features "debug-symbols"
```

### Cross-compilation (Future)
```powershell
# Install ARM64 target (when supported)
rustup target add aarch64-pc-windows-msvc

# Build for ARM64
cargo build --target aarch64-pc-windows-msvc --release
```

## 🔧 Development Workflow

### Environment Setup
```powershell
# Copy environment template
copy .env.example .env

# Edit configuration
notepad .env
```

Example `.env`:
```bash
# Development settings
RUST_LOG=debug
PROCESS_GUARD_CONFIG_PATH=./dev-config.toml
PROCESS_GUARD_LOG_LEVEL=debug

# Test settings
TEST_TIMEOUT=60
INTEGRATION_TESTS=true

# Build settings
CARGO_TARGET_DIR=./target
RUSTFLAGS="-C link-arg=/DEBUG"
```

### Development Build Script
```powershell
# Create build.ps1
@'
#!/usr/bin/env pwsh
param(
    [string]$Target = "debug",
    [switch]$Test,
    [switch]$Clippy,
    [switch]$Format,
    [switch]$Clean
)

if ($Clean) {
    Write-Host "Cleaning build artifacts..."
    cargo clean
}

if ($Format) {
    Write-Host "Formatting code..."
    cargo fmt --all
}

if ($Clippy) {
    Write-Host "Running clippy..."
    cargo clippy --all-targets --all-features -- -D warnings
}

switch ($Target) {
    "debug" {
        Write-Host "Building debug..."
        cargo build
    }
    "release" {
        Write-Host "Building release..."
        cargo build --release
    }
    "all" {
        Write-Host "Building all targets..."
        cargo build --all-targets --all-features
    }
}

if ($Test) {
    Write-Host "Running tests..."
    cargo test --all-features
}

Write-Host "Build complete!"
'@ | Out-File build.ps1

# Make executable
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Usage examples
.\build.ps1 -Target debug -Test -Clippy
.\build.ps1 -Target release
.\build.ps1 -Clean -Target all -Test
```

### Watch Mode Development
```powershell
# Install cargo-watch if not already installed
cargo install cargo-watch

# Watch and rebuild on changes
cargo watch -x build

# Watch and test on changes
cargo watch -x test

# Watch specific directory
cargo watch -w src -x "build --bin process-guard"

# Custom watch command
cargo watch -x "clippy --all-targets -- -D warnings" -x test
```

## 🧪 Testing

### Test Categories
```powershell
# Unit tests
cargo test --lib

# Integration tests
cargo test --test integration

# Documentation tests
cargo test --doc

# Specific test
cargo test detection::direct_syscalls

# Test with output
cargo test -- --nocapture

# Test specific feature
cargo test --features "etw" detection::etw
```

### Performance Tests
```powershell
# Benchmark tests
cargo bench

# Compare benchmarks
cargo benchcmp baseline.txt new.txt

# Profile specific benchmark
cargo bench --bench detection_bench -- --profile-time=30
```

### Code Coverage
```powershell
# Generate coverage report
cargo tarpaulin --out Html --output-dir coverage/

# Coverage with specific features
cargo tarpaulin --features "etw,ml" --out Html

# CI coverage (no HTML)
cargo tarpaulin --out Xml
```

### Test Configuration
Create `tests/config.toml`:
```toml
[test]
timeout_seconds = 60
parallel = true
fail_fast = false

[integration]
enabled = true
create_test_processes = true
cleanup_on_failure = true

[performance]
benchmark_iterations = 1000
measurement_time_sec = 10
```

## 📦 Distribution Builds

### Release Build Script
```powershell
# release.ps1
param(
    [Parameter(Mandatory=$true)]
    [string]$Version,
    [switch]$Sign,
    [switch]$Package
)

Write-Host "Building Process Guard v$Version for release..."

# Clean previous builds
cargo clean

# Verify version in Cargo.toml
$CargoToml = Get-Content Cargo.toml
if ($CargoToml -notmatch "version = `"$Version`"") {
    Write-Error "Version mismatch in Cargo.toml"
    exit 1
}

# Build optimized release
cargo build --release --all-features

# Run full test suite
Write-Host "Running test suite..."
cargo test --release --all-features
if ($LASTEXITCODE -ne 0) {
    Write-Error "Tests failed"
    exit 1
}

# Security audit
Write-Host "Running security audit..."
cargo audit
if ($LASTEXITCODE -ne 0) {
    Write-Error "Security vulnerabilities found"
    exit 1
}

# Code quality checks
Write-Host "Running code quality checks..."
cargo clippy --release --all-features -- -D warnings
if ($LASTEXITCODE -ne 0) {
    Write-Error "Code quality issues found"
    exit 1
}

$BinaryPath = "target\release\process-guard.exe"

if ($Sign) {
    Write-Host "Signing binary..."
    # Add your code signing logic here
    # signtool sign /tr http://timestamp.digicert.com /td sha256 /f certificate.p12 /p password $BinaryPath
}

if ($Package) {
    Write-Host "Creating distribution package..."
    $PackageDir = "dist\process-guard-$Version"
    New-Item -ItemType Directory -Path $PackageDir -Force

    # Copy files
    Copy-Item $BinaryPath -Destination "$PackageDir\process-guard.exe"
    Copy-Item "README.md" -Destination $PackageDir
    Copy-Item "LICENSE" -Destination $PackageDir
    Copy-Item "config.example.toml" -Destination "$PackageDir\config.toml"

    # Create archive
    Compress-Archive -Path "$PackageDir\*" -DestinationPath "dist\process-guard-$Version-windows-x64.zip" -Force

    Write-Host "Package created: dist\process-guard-$Version-windows-x64.zip"
}

Write-Host "Release build complete!"
```

### Docker Build
```dockerfile
# Dockerfile.build
FROM mcr.microsoft.com/windows/servercore:ltsc2022 AS builder

# Install Rust
SHELL ["powershell", "-Command"]
RUN Invoke-WebRequest -Uri "https://win.rustup.rs/x86_64" -OutFile "rustup-init.exe"; \
    .\rustup-init.exe -y; \
    Remove-Item .\rustup-init.exe

# Set environment
ENV PATH="C:\\Users\\ContainerUser\\.cargo\\bin:${PATH}"

# Install build tools
RUN rustup component add clippy rustfmt

# Copy source
WORKDIR C:\build
COPY . .

# Build
RUN cargo build --release --all-features

# Runtime image
FROM mcr.microsoft.com/windows/nanoserver:ltsc2022
WORKDIR C:\ProcessGuard
COPY --from=builder C:\build\target\release\process-guard.exe .
CMD ["process-guard.exe", "--help"]
```

Build with Docker:
```powershell
# Build image
docker build -f Dockerfile.build -t process-guard:build .

# Extract binary
docker create --name pg-temp process-guard:build
docker cp pg-temp:/ProcessGuard/process-guard.exe ./process-guard.exe
docker rm pg-temp
```

## 🔍 Debugging

### Debug Build Configuration
```toml
# .cargo/config.toml
[target.x86_64-pc-windows-msvc]
rustflags = ["-C", "link-arg=/DEBUG:FULL"]

[build]
target = "x86_64-pc-windows-msvc"
```

### Visual Studio Code Setup
Create `.vscode/launch.json`:
```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "type": "cppvsdbg",
            "request": "launch",
            "name": "Debug Process Guard",
            "program": "${workspaceFolder}/target/debug/process-guard.exe",
            "args": ["monitor", "--verbose"],
            "cwd": "${workspaceFolder}",
            "environment": [
                {"name": "RUST_LOG", "value": "debug"}
            ],
            "console": "externalTerminal",
            "stopAtEntry": false
        },
        {
            "type": "cppvsdbg",
            "request": "launch",
            "name": "Debug Tests",
            "program": "${workspaceFolder}/target/debug/deps/process_guard-*.exe",
            "args": ["--nocapture"],
            "cwd": "${workspaceFolder}",
            "environment": [
                {"name": "RUST_LOG", "value": "debug"}
            ],
            "console": "internalConsole",
            "stopAtEntry": false
        }
    ]
}
```

### Debugging Commands
```powershell
# Debug build with symbols
cargo build --features "debug-symbols"

# Run with debugger
windbg target\debug\process-guard.exe

# Debug specific test
cargo test --no-run
windbg target\debug\deps\process_guard-*.exe

# Memory debugging with Application Verifier
# (Requires Windows SDK)
appverif /verify target\debug\process-guard.exe
```

## ⚡ Performance Optimization

### Profile-Guided Optimization (PGO)
```powershell
# Stage 1: Build with instrumentation
$env:RUSTFLAGS = "-C profile-generate=./pgo-data"
cargo build --release

# Stage 2: Generate profile data
.\target\release\process-guard.exe benchmark --all --iterations 1000

# Stage 3: Build with profile data
$env:RUSTFLAGS = "-C profile-use=./pgo-data"
cargo build --release
```

### Link-Time Optimization
```toml
# Cargo.toml
[profile.release]
lto = true                    # Enable LTO
codegen-units = 1            # Single codegen unit for better optimization
panic = "abort"              # Remove panic handling code
strip = true                 # Strip debug symbols
```

### Size Optimization
```toml
# Cargo.toml for minimal size
[profile.release]
opt-level = "s"              # Optimize for size
lto = true
codegen-units = 1
panic = "abort"
strip = true

[dependencies]
# Use minimal feature sets
tokio = { version = "1.0", features = ["rt-multi-thread"] }
```

## 📊 Build Metrics

### Compilation Time Analysis
```powershell
# Measure compilation time
cargo build --timings

# Parallel compilation analysis
cargo build -Z timings

# Dependency build time
cargo tree --duplicates
```

### Binary Analysis
```powershell
# Check binary size
dir target\release\process-guard.exe

# Analyze binary sections
dumpbin /headers target\release\process-guard.exe

# Dependency analysis
cargo bloat --release --crates
cargo bloat --release --filter process-guard
```

## 🚨 Troubleshooting

### Common Build Issues

#### Linker Errors
```powershell
# Issue: LNK2019 unresolved external symbol
# Solution: Install Visual Studio Build Tools with MSVC

# Issue: Cannot find vcvarsall.bat
# Solution: Reinstall Visual Studio Build Tools
```

#### Dependency Issues
```powershell
# Update dependencies
cargo update

# Check for outdated dependencies
cargo outdated

# Audit for security vulnerabilities
cargo audit
```

#### Memory Issues During Build
```powershell
# Reduce parallel compilation
$env:CARGO_BUILD_JOBS = "2"
cargo build --release

# Use release mode for dependencies
$env:CARGO_PROFILE_DEV_OPT_LEVEL = "1"
cargo build
```

### Build Environment Reset
```powershell
# Clean everything
cargo clean
Remove-Item -Recurse -Force target/

# Reset Rust installation
rustup self uninstall
# Reinstall Rust following prerequisites section
```

## 📚 Additional Resources

### Documentation
```powershell
# Generate and open documentation
cargo doc --open --all-features

# Build mdbook documentation
cd docs
mdbook build
mdbook serve --open
```

### Continuous Integration
See `.github/workflows/build.yml` for CI/CD pipeline configuration.

### IDE Support
- **Visual Studio Code**: rust-analyzer extension
- **Visual Studio**: VisualRust extension
- **CLion**: Rust plugin
- **IntelliJ IDEA**: Rust plugin

---

## 🎯 Next Steps

After successful build:
1. **[Testing Guide](./testing.md)** - Comprehensive testing strategies
2. **[Contributing](./contributing.md)** - How to contribute changes
3. **[Debugging](./debugging.md)** - Advanced debugging techniques
4. **[Performance](../technical/performance.md)** - Performance analysis and optimization