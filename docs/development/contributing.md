# Contributing to Process Guard

Thank you for your interest in contributing to Process Guard! This guide will help you get started with contributing code, documentation, or reporting issues.

## 🚀 Quick Start for Contributors

### 1. Setup Development Environment
```bash
# Clone the repository
git clone https://github.com/xrer/process-guard.git
cd process-guard

# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Install required tools
rustup component add clippy rustfmt
cargo install cargo-tarpaulin  # For code coverage

# Build the project
cargo build

# Run tests to ensure everything works
cargo test --all-features
```

### 2. Fork and Branch
```bash
# Fork on GitHub, then clone your fork
git clone https://github.com/YOUR_USERNAME/process-guard.git
cd process-guard

# Add upstream remote
git remote add upstream https://github.com/xrer/process-guard.git

# Create a feature branch
git checkout -b feature/your-amazing-feature
```

### 3. Make Your Changes
- Write code following our [coding standards](#coding-standards)
- Add tests for new functionality
- Update documentation if needed
- Ensure all tests pass

### 4. Submit Pull Request
```bash
# Commit your changes
git add .
git commit -m "Add amazing new detection technique"

# Push to your fork
git push origin feature/your-amazing-feature

# Create pull request on GitHub
```

## 🎯 Areas for Contribution

### 🛡️ Detection Techniques (High Priority)
**What we need:**
- New injection methods detection
- Evasion technique counters
- Performance optimizations
- False positive reduction

**Examples:**
- Fiber-based injection detection
- AMSI bypass detection
- Hardware breakpoint injection
- Return-oriented programming (ROP) detection

**Getting Started:**
1. Check [detection issues](https://github.com/xrer/process-guard/labels/detection)
2. Read [Detection Development Guide](./detection-development.md)
3. Look at existing detections in `src/detections/`

### 🔧 API & Integration (Medium Priority)
**What we need:**
- New API endpoints
- Client library improvements
- WebSocket event enhancements
- Authentication methods

**Examples:**
- GraphQL API support
- SIEM integration plugins
- Real-time dashboard improvements
- Mobile client libraries

### 📊 Performance & Optimization (Medium Priority)
**What we need:**
- Memory usage reduction
- CPU optimization
- I/O efficiency improvements
- Benchmarking enhancements

**Focus Areas:**
- ETW event processing optimization
- Memory scanning algorithms
- Caching strategies
- Parallel processing improvements

### 📚 Documentation & Tutorials (Always Welcome)
**What we need:**
- Code examples and tutorials
- API documentation improvements
- Troubleshooting guides
- Video tutorials

### 🧪 Testing & Quality Assurance
**What we need:**
- Unit test coverage improvements
- Integration test scenarios
- Benchmark test development
- Continuous integration enhancements

## 📋 Contribution Guidelines

### Code Contributions

#### Before You Start
1. **Check existing issues** - Look for related work or discussions
2. **Open an issue** - For substantial changes, discuss first
3. **Review architecture** - Understand the codebase structure
4. **Read coding standards** - Follow our conventions

#### Development Process
1. **Write tests first** - Test-driven development preferred
2. **Keep commits focused** - One logical change per commit
3. **Write clear commit messages** - Follow conventional commit format
4. **Update documentation** - Keep docs in sync with code changes
5. **Run full test suite** - Ensure nothing breaks

#### Pull Request Requirements
- [ ] All tests pass (`cargo test --all-features`)
- [ ] Code coverage maintained or improved
- [ ] Documentation updated (if applicable)
- [ ] Changelog updated (for user-facing changes)
- [ ] Code formatted (`cargo fmt`)
- [ ] No clippy warnings (`cargo clippy`)
- [ ] Performance impact assessed (for core changes)

### Documentation Contributions

#### Types of Documentation
- **API Documentation** - Inline code docs and OpenAPI specs
- **User Guides** - How-to guides and tutorials
- **Technical Documentation** - Architecture and design docs
- **Examples** - Code samples and real-world scenarios

#### Documentation Standards
- Use clear, concise language
- Include runnable code examples
- Add diagrams for complex concepts
- Keep information current and accurate
- Follow markdown best practices

### Bug Reports

#### Before Reporting
1. **Search existing issues** - Check if already reported
2. **Try latest version** - Ensure bug exists in current release
3. **Isolate the problem** - Minimize reproduction steps
4. **Gather information** - Collect logs, system info, etc.

#### Bug Report Template
```markdown
**Description**
A clear description of the bug.

**Reproduction Steps**
1. Step one
2. Step two
3. See error

**Expected Behavior**
What you expected to happen.

**Actual Behavior**
What actually happened.

**Environment**
- OS: Windows 10 (Version 2004)
- Rust Version: 1.70.0
- Process Guard Version: 0.3.1

**Additional Context**
- Log files (attach if relevant)
- Configuration files
- Screenshots/videos (if applicable)
```

### Feature Requests

#### Feature Request Template
```markdown
**Feature Description**
Clear description of the proposed feature.

**Use Case**
Explain the problem this feature would solve.

**Proposed Solution**
Describe your preferred implementation approach.

**Alternatives Considered**
Other approaches you've considered.

**Additional Context**
Screenshots, mockups, references to similar tools.
```

## 🔧 Development Guidelines

### Coding Standards

#### Rust Style Guidelines
```rust
// Use descriptive variable names
let detection_confidence = 0.95;  // ✅ Good
let conf = 0.95;                   // ❌ Avoid

// Structure code logically
pub struct DirectSyscallDetector {
    patterns: Vec<SyscallPattern>,
    confidence_threshold: f32,
}

impl DirectSyscallDetector {
    pub fn new(threshold: f32) -> Self {
        Self {
            patterns: Self::load_default_patterns(),
            confidence_threshold: threshold,
        }
    }

    // Public interface first, private methods last
    pub async fn scan_process(&self, pid: u32) -> Result<Detection> {
        self.validate_permissions(pid)?;
        self.perform_scan(pid).await
    }

    fn validate_permissions(&self, pid: u32) -> Result<()> {
        // Implementation
    }
}
```

#### Error Handling
```rust
// Use thiserror for error definitions
#[derive(Error, Debug)]
pub enum DetectionError {
    #[error("Process {pid} not found")]
    ProcessNotFound { pid: u32 },

    #[error("Access denied to process {pid}")]
    AccessDenied { pid: u32 },

    #[error("Invalid pattern: {pattern}")]
    InvalidPattern { pattern: String },
}

// Use Result types consistently
pub async fn detect_injection(pid: u32) -> Result<Detection, DetectionError> {
    // Implementation
}
```

#### Testing Patterns
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_direct_syscall_detection() {
        // Arrange
        let detector = DirectSyscallDetector::new(0.8);
        let test_pid = 1234;

        // Act
        let result = detector.scan_process(test_pid).await;

        // Assert
        assert!(result.is_ok());
        let detection = result.unwrap();
        assert_eq!(detection.technique, InjectionType::DirectSyscalls);
    }

    #[test]
    fn test_pattern_matching() {
        // Test specific functionality with isolated unit tests
    }
}
```

### Performance Guidelines

#### Memory Management
- Use `Arc` for shared immutable data
- Use `Mutex`/`RwLock` sparingly, prefer channels
- Avoid unnecessary allocations in hot paths
- Use `&str` instead of `String` when possible

#### Async Programming
- Use `tokio` for async runtime
- Prefer `async`/`await` over manual future combinators
- Use `tokio::spawn` for CPU-bound tasks
- Implement proper cancellation for long-running tasks

#### Benchmarking
```rust
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_detection_latency(c: &mut Criterion) {
    c.bench_function("syscall_detection", |b| {
        b.iter(|| {
            // Benchmark code
            let result = detect_syscalls(black_box(1234));
            black_box(result)
        })
    });
}

criterion_group!(benches, bench_detection_latency);
criterion_main!(benches);
```

## 🔍 Code Review Process

### What Reviewers Look For

#### Technical Quality
- **Correctness** - Does the code work as intended?
- **Performance** - Is it efficient for the use case?
- **Security** - Are there potential vulnerabilities?
- **Maintainability** - Is it easy to understand and modify?

#### Code Standards
- **Style consistency** - Follows project conventions
- **Documentation** - Adequate inline and API docs
- **Testing** - Appropriate test coverage
- **Error handling** - Proper error propagation

### Review Response Guidelines

#### For Authors
- **Be responsive** - Reply to comments promptly
- **Ask questions** - Clarify unclear feedback
- **Make changes** - Address reviewer concerns
- **Learn and improve** - Use feedback to grow

#### For Reviewers
- **Be constructive** - Offer solutions, not just criticism
- **Explain reasoning** - Help authors understand the "why"
- **Approve when ready** - Don't hold up good contributions
- **Respect effort** - Acknowledge the work put in

## 🏷️ Release Process

### Version Numbering
We follow [Semantic Versioning](https://semver.org/):
- **MAJOR** - Breaking API changes
- **MINOR** - New features (backward compatible)
- **PATCH** - Bug fixes (backward compatible)

### Release Checklist
- [ ] All tests passing
- [ ] Documentation updated
- [ ] Changelog updated
- [ ] Performance benchmarks run
- [ ] Security review completed
- [ ] Version numbers updated

## 🤝 Community Guidelines

### Code of Conduct
We expect all contributors to follow our [Code of Conduct](../CODE_OF_CONDUCT.md):
- Be respectful and inclusive
- Welcome newcomers and help them learn
- Focus on constructive feedback
- Maintain professional communication

### Communication Channels
- **GitHub Issues** - Bug reports, feature requests
- **GitHub Discussions** - General questions, ideas
- **Pull Requests** - Code review discussions
- **Security Issues** - Private security reporting

### Recognition
Contributors are recognized in:
- **Changelog** - Major contributions noted
- **README** - Contributor acknowledgments
- **Release Notes** - Feature attribution

## 📊 Contribution Statistics

### Current Contributors
- **Core Team**: 3 members
- **Regular Contributors**: 8 developers
- **Community Contributors**: 25+ individuals
- **Documentation Contributors**: 15+ writers

### Contribution Areas (Last 6 Months)
- **Detection Techniques**: 45% of contributions
- **Performance Improvements**: 25%
- **Documentation**: 20%
- **Bug Fixes**: 10%

## 🎯 Roadmap & Priorities

### Upcoming Milestones
- **v0.4.0** - Fiber injection detection, AMSI bypass detection
- **v0.5.0** - Hardware breakpoint detection, improved ML engine
- **v1.0.0** - Production-ready release, comprehensive documentation

### Priority Areas for Contributors
1. **Critical** - Security vulnerabilities, major bugs
2. **High** - New detection techniques, performance issues
3. **Medium** - API improvements, documentation
4. **Low** - Code cleanup, minor enhancements

---

## 🎉 Thank You!

Every contribution, no matter how small, helps make Process Guard better for the entire security community. We appreciate your time and effort!

**Questions?** Feel free to:
- Open a [discussion](https://github.com/xrer/process-guard/discussions)
- Join our community calls (schedule in discussions)
- Reach out to maintainers directly

**Ready to contribute?** Start with a [good first issue](https://github.com/xrer/process-guard/labels/good%20first%20issue) and let's build something amazing together!