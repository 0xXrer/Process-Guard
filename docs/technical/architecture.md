# Process Guard Architecture

System architecture and design overview for Process Guard.

## 🏗️ High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     User Interfaces                          │
├──────────────┬──────────────┬──────────────┬────────────────┤
│     CLI      │   REST API   │  WebSocket   │   Dashboard    │
└──────┬───────┴──────┬───────┴──────┬───────┴───────┬────────┘
       │              │              │               │
       └──────────────┴──────────────┴───────────────┘
                          │
       ┌──────────────────┴──────────────────┐
       │      Process Guard Core Engine       │
       ├──────────────────────────────────────┤
       │  • Event Router                      │
       │  • Configuration Manager             │
       │  • Process Registry                  │
       │  • Alert Manager                     │
       └──────────────┬───────────────────────┘
                      │
       ┌──────────────┴───────────────────────┐
       │       Detection Engine Layer          │
       ├───────────┬──────────┬───────────────┤
       │ Syscall   │ WoW64    │ Memory        │
       │ Detector  │ Monitor  │ Scanner       │
       ├───────────┼──────────┼───────────────┤
       │ TxF       │ Thread   │ ETW           │
       │ Monitor   │ Monitor  │ Protection    │
       └───────┬───┴────┬─────┴───────┬───────┘
               │        │             │
       ┌───────┴────────┴─────────────┴───────┐
       │      Data Collection Layer            │
       ├───────────────────────────────────────┤
       │  • ETW Session Manager                │
       │  • Process Memory Reader              │
       │  • Kernel Interface                   │
       │  • WoW64 Context Reader               │
       └───────────────┬───────────────────────┘
                       │
       ┌───────────────┴───────────────────────┐
       │        Windows Kernel APIs             │
       ├───────────────────────────────────────┤
       │  ETW │ NTDLL │ Kernel32 │ WoW64      │
       └───────────────────────────────────────┘
```

## 🧩 Core Components

### 1. User Interface Layer

#### CLI Interface (`src/cli.rs`)
- Command-line tool for monitoring and scanning
- Real-time statistics display
- Process listing and filtering
- Rule export functionality

**Key Features**:
- Subcommand-based architecture
- JSON output support for scripting
- Interactive and non-interactive modes
- Progress indicators for long operations

#### REST API (`src/api/mod.rs`)
- HTTP server using `actix-web` framework
- RESTful endpoints for all functionality
- JWT or token-based authentication
- Rate limiting and request validation

**Endpoints**:
- `/api/processes` - Process listing and filtering
- `/api/syscalls` - Syscall detection
- `/api/wow64` - WoW64 monitoring
- `/api/detections` - Detection history
- `/api/config` - Runtime configuration

#### WebSocket API (`src/websocket.rs`)
- Real-time event streaming
- Bidirectional communication
- Event subscription model
- Automatic reconnection support

**Event Types**:
- Detection events (new threats detected)
- Process events (process start/stop)
- Syscall events (suspicious syscalls)
- WoW64 transition events
- System health events

### 2. Core Engine Layer

#### Event Router
- Centralized event distribution
- Event filtering and prioritization
- Subscriber management
- Event buffering and rate limiting

#### Configuration Manager
- Hot-reload configuration support
- Validation and schema enforcement
- Default configuration handling
- Environment-specific overrides

#### Process Registry
- Maintains state of monitored processes
- Caches process metadata
- Tracks detection history per process
- Manages whitelists/blacklists

#### Alert Manager
- Aggregates detection events
- De-duplicates alerts
- Manages alert severity
- Integrates with external systems (SIEM, webhooks)

### 3. Detection Engine Layer

#### Syscall Detector (`src/detector.rs`)
**Purpose**: Detect direct syscall invocations bypassing ntdll.dll

**Detection Methods**:
1. **Pattern Matching**
   - Identifies SysWhispers templates
   - Detects inline syscall instructions (`syscall`, `int 2Eh`)
   - Recognizes syscall number patterns

2. **Stack Validation**
   - Verifies return addresses
   - Checks if code originates from ntdll.dll
   - Identifies anomalous call stacks

3. **ETW Integration**
   - Monitors kernel syscall events
   - Correlates with user-mode calls
   - Detects mismatches

**Performance**: 0.3ms average detection latency

#### WoW64 Monitor (`src/heavens_gate.rs`)
**Purpose**: Detect Heaven's Gate (32-bit to 64-bit transitions)

**Detection Methods**:
1. **Segment Monitoring**
   - Tracks CS register changes (0x23 → 0x33)
   - Monitors far jumps/returns
   - Detects x64 code in x32 processes

2. **Memory Region Analysis**
   - Scans for x64 code patterns (REX prefixes)
   - Identifies 64-bit address space access
   - Validates instruction encoding

3. **Transition Tracking**
   - Records transition frequency
   - Identifies anomalous patterns
   - Builds behavioral baseline

**Performance**: 1.2ms average detection latency

#### Memory Scanner
**Purpose**: Detect process hollowing and memory-based injections

**Detection Methods**:
1. **Memory Region Analysis**
   - Scans for executable regions
   - Compares with disk image
   - Identifies mismatches

2. **PE Header Validation**
   - Verifies PE headers in memory
   - Checks section characteristics
   - Validates entry points

3. **Code Integrity**
   - Hashes executable sections
   - Compares with known-good values
   - Detects modifications

**Performance**: 2.5ms per process scan

#### TxF Monitor (`src/txf.rs`)
**Purpose**: Detect Process Doppelgänging via TxF

**Detection Methods**:
1. **Transaction Monitoring**
   - Hooks TxF APIs
   - Tracks transaction lifecycle
   - Monitors rollback operations

2. **File Creation Tracking**
   - Monitors transacted file creation
   - Correlates with process creation
   - Detects suspicious timing

**Performance**: Real-time monitoring, <0.5ms overhead

#### Thread Monitor
**Purpose**: Detect thread hijacking

**Detection Methods**:
1. **Context Monitoring**
   - Tracks thread context changes
   - Monitors instruction pointer changes
   - Detects anomalous jumps

2. **Thread Creation**
   - Monitors remote thread creation
   - Validates thread start addresses
   - Checks for suspicious entry points

#### ETW Protection (`src/etw_protection.rs`)
**Purpose**: Prevent ETW patching and self-protection

**Detection Methods**:
1. **Self-Integrity Checks**
   - Validates own process memory
   - Monitors callback tampering
   - Detects code modifications

2. **ETW Callback Protection**
   - Verifies ETW callback addresses
   - Monitors callback list
   - Detects inline hooks

### 4. Data Collection Layer

#### ETW Session Manager (`src/etw.rs`)
**Purpose**: Manage Event Tracing for Windows sessions

**Capabilities**:
- Kernel event collection
- Process/Thread events
- Image load events
- Registry/File events
- Network events

**Architecture**:
```rust
ETW Session
    ├── Kernel Provider
    │   ├── Process Events
    │   ├── Thread Events
    │   └── Image Load Events
    ├── Security Provider
    │   ├── Audit Events
    │   └── Token Events
    └── Custom Providers
        └── Syscall Events
```

#### Process Memory Reader
**Purpose**: Safe cross-process memory access

**Features**:
- Handle management
- Permission checking
- Memory protection handling
- Error recovery

#### Kernel Interface
**Purpose**: Low-level Windows kernel interaction

**Capabilities**:
- Syscall invocation
- Kernel object access
- Device I/O control
- Driver communication

### 5. Machine Learning Engine (`src/ml.rs`)

**Purpose**: Behavioral analysis and anomaly detection

**Architecture**:
```
Data Collection → Feature Extraction → Model Inference → Classification
      ↓                  ↓                    ↓               ↓
  Process data      Normalize         Trained model    Benign/Suspicious
  API calls         Statistical       Decision tree    Confidence score
  Memory ops        Time series       Random forest    Alert generation
  Network           Patterns
```

**Features**:
- Online learning (adapts to environment)
- Anomaly detection
- Behavioral profiling
- Confidence scoring

**Performance**:
- Model update: every 3600s
- Inference: <5ms per process
- Memory: ~10MB model size

## 🔄 Data Flow

### Detection Flow Example: Direct Syscall Detection

```
1. ETW Event Triggered
   └─→ Syscall execution detected by kernel provider

2. Event Router
   └─→ Routes to Syscall Detector

3. Syscall Detector Analysis
   ├─→ Pattern matching (check for syscall instruction)
   ├─→ Stack validation (verify return address)
   └─→ Confidence calculation

4. ML Engine Validation
   └─→ Behavioral analysis confirms anomaly

5. Alert Manager
   ├─→ Create detection alert
   ├─→ Update process registry
   └─→ Send to subscribers (API, WebSocket, CLI)

6. Response Actions
   ├─→ Log to file
   ├─→ Send to SIEM
   ├─→ Trigger webhook
   └─→ Optional: Terminate process (if configured)
```

## 🔐 Security Architecture

### Privilege Management
```
Process Start
    ↓
Check Admin Rights → Fail: Exit with error
    ↓
Enable SeDebugPrivilege → Fail: Warn and continue
    ↓
Drop unnecessary privileges (if configured)
    ↓
Run with minimal required rights
```

### Self-Protection
1. **Code Integrity**
   - Validates own executable signature
   - Monitors own memory regions
   - Detects tampering attempts

2. **ETW Protection**
   - Validates callback pointers
   - Detects inline hooks
   - Monitors provider state

3. **API Protection**
   - Rate limiting
   - Authentication enforcement
   - Input validation

## 📊 Performance Architecture

### Multi-threading Model

```
Main Thread
    ├─→ CLI Interface
    └─→ Configuration Management

ETW Thread Pool (4-8 threads)
    ├─→ Event Processing
    └─→ Buffer management

Detection Thread Pool (4-8 threads)
    ├─→ Syscall detection
    ├─→ Memory scanning
    └─→ Pattern matching

API Thread Pool (configurable)
    └─→ HTTP request handling

Background Tasks
    ├─→ ML model updates (every 3600s)
    ├─→ Process registry cleanup
    └─→ Log rotation
```

### Caching Strategy

```
L1 Cache (In-Memory, Fast)
    ├─→ Recent detections (1000 entries)
    ├─→ Process metadata (500 entries)
    └─→ Syscall patterns (100 entries)

L2 Cache (Disk, Persistent)
    ├─→ Historical detections
    └─→ ML model checkpoints
```

### Resource Limits

| Resource | Default Limit | Configurable |
|----------|---------------|--------------|
| Memory   | 512 MB        | Yes          |
| CPU      | 5%            | Yes          |
| Disk I/O | Best effort   | No           |
| Network  | 1 Mbps        | Yes          |

## 🔧 Configuration Architecture

### Configuration Hierarchy

```
1. Default Configuration (embedded in binary)
    ↓
2. System Configuration (/etc/process-guard/config.toml)
    ↓
3. User Configuration (~/.process-guard/config.toml)
    ↓
4. Environment Variables (PROCESS_GUARD_*)
    ↓
5. Command-line Arguments (--option=value)
```

### Hot-Reload Support

Configuration changes are detected and applied without restart:
- Detection sensitivity adjustments
- Whitelist/blacklist updates
- Performance tuning
- Logging configuration

**Not hot-reloadable**:
- API port changes
- ETW provider changes
- Privilege requirements

## 🚀 Deployment Architectures

### Standalone Mode
```
Single Windows Machine
    └─→ Process Guard
        ├─→ ETW monitoring
        ├─→ Local API (127.0.0.1)
        └─→ File logging
```

### Enterprise Mode
```
Multiple Windows Machines
    ├─→ Process Guard (Agent)
    │   ├─→ Local detection
    │   └─→ API client
    └─→ Central Management Server
        ├─→ Aggregation API
        ├─→ Dashboard
        └─→ SIEM integration
```

### Cloud-Integrated Mode
```
Windows VMs (Cloud)
    ├─→ Process Guard (Agent)
    │   └─→ Webhook to cloud
    └─→ Cloud SIEM (Azure Sentinel, Splunk)
        ├─→ Alert aggregation
        ├─→ Threat intelligence
        └─→ Response automation
```

## 📚 Additional Resources

- [ETW Integration Details](./etw.md)
- [TxF Monitoring](./txf.md)
- [Machine Learning Engine](./ml.md)
- [Performance Tuning](./performance.md)

---

**Last Updated**: 2025-11-16
**Version**: 0.3.1
