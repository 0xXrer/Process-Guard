# Syscalls API

Мониторинг системных вызовов и детекция direct syscalls/SysWhispers.

## GET /syscalls

Получить информацию о мониторинге syscalls.

### Query Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `pid` | integer | - | Фильтр по Process ID |
| `direct_only` | boolean | false | Только direct syscalls |
| `since` | integer | - | Unix timestamp (фильтр по времени) |
| `limit` | integer | 100 | Максимальное количество результатов |
| `offset` | integer | 0 | Смещение для пагинации |
| `syscall_number` | integer | - | Фильтр по номеру syscall |

### Example Request

```bash
curl -H "Authorization: Bearer your-token" \
     "http://127.0.0.1:8080/api/syscalls?direct_only=true&limit=50"
```

### Example Response

```json
{
  "data": {
    "syscalls": [
      {
        "id": "syscall_001",
        "pid": 1234,
        "process_name": "malware.exe",
        "syscall_number": 24,
        "syscall_name": "NtCreateFile",
        "return_address": "0x401000",
        "is_direct": true,
        "confidence": 0.89,
        "stack_frames": [
          {
            "return_address": "0x401000",
            "frame_pointer": "0x1000",
            "module_name": "malware.exe",
            "module_base": "0x400000",
            "offset": "0x1000"
          },
          {
            "return_address": "0x7FFE0000",
            "frame_pointer": "0x2000",
            "module_name": "ntdll.dll",
            "module_base": "0x7FFE0000",
            "offset": "0x0"
          }
        ],
        "pattern_matched": "direct_syscall_x64",
        "timestamp": 1699123456,
        "threat_level": "HIGH"
      }
    ],
    "pagination": {
      "total": 150,
      "limit": 50,
      "offset": 0,
      "has_more": true
    }
  },
  "meta": {
    "direct_syscalls": 15,
    "total_syscalls": 150,
    "monitoring_active": true,
    "timestamp": 1699123456
  }
}
```

### Threat Levels

| Level | Description | Confidence Range |
|-------|-------------|------------------|
| `LOW` | Подозрительно | 0.0 - 0.3 |
| `MEDIUM` | Вероятная угроза | 0.3 - 0.7 |
| `HIGH` | Высокая угроза | 0.7 - 0.9 |
| `CRITICAL` | Критическая угроза | 0.9 - 1.0 |

### Pattern Types

| Pattern | Description |
|---------|-------------|
| `direct_syscall_x64` | mov r10, rcx; mov eax, <num>; syscall |
| `minimal_syscall` | mov eax, <num>; syscall; ret |
| `syswhispers_template` | SysWhispers2/3 шаблон |
| `indirect_syscall` | Непрямые syscalls через указатели |

---

## GET /syscalls/{id}

Детальная информация о конкретном syscall.

### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Syscall ID |

### Example Request

```bash
curl -H "Authorization: Bearer your-token" \
     "http://127.0.0.1:8080/api/syscalls/syscall_001"
```

### Example Response

```json
{
  "data": {
    "id": "syscall_001",
    "pid": 1234,
    "process_name": "malware.exe",
    "syscall_number": 24,
    "syscall_name": "NtCreateFile",
    "return_address": "0x401000",
    "is_direct": true,
    "confidence": 0.89,
    "disassembly": [
      {
        "address": "0x401000",
        "instruction": "mov r10, rcx",
        "bytes": "4C8BD1"
      },
      {
        "address": "0x401003",
        "instruction": "mov eax, 0x18",
        "bytes": "B818000000"
      },
      {
        "address": "0x401008",
        "instruction": "syscall",
        "bytes": "0F05"
      }
    ],
    "stack_trace": [
      {
        "return_address": "0x401000",
        "frame_pointer": "0x1000",
        "module_name": "malware.exe",
        "module_base": "0x400000",
        "function": "unknown",
        "validated": false
      }
    ],
    "detection_details": {
      "pattern_matched": "direct_syscall_x64",
      "validation_failed": [
        "stack_not_from_ntdll",
        "inline_syscall_detected"
      ],
      "bypass_indicators": [
        "syswhispers_signature",
        "evasion_patterns"
      ]
    },
    "timestamp": 1699123456,
    "threat_level": "HIGH"
  }
}
```

---

## POST /syscalls/scan

Запустить активное сканирование для поиска inline syscalls.

### Request Body

```json
{
  "pid": 1234,
  "scan_type": "deep",
  "memory_regions": [
    {
      "base": "0x400000",
      "size": 1048576
    }
  ],
  "patterns": ["all"],
  "include_stack_traces": true
}
```

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `pid` | integer | required | Process ID для сканирования |
| `scan_type` | string | "quick" | quick, deep, full |
| `memory_regions` | array | - | Конкретные регионы памяти |
| `patterns` | array | ["all"] | Паттерны для поиска |
| `include_stack_traces` | boolean | true | Включить stack traces |

### Example Request

```bash
curl -X POST \
     -H "Authorization: Bearer your-token" \
     -H "Content-Type: application/json" \
     -d '{"pid": 1234, "scan_type": "deep"}' \
     "http://127.0.0.1:8080/api/syscalls/scan"
```

### Example Response

```json
{
  "data": {
    "scan_id": "syscall_scan_001",
    "pid": 1234,
    "scan_type": "deep",
    "start_time": "2023-11-06T12:00:00Z",
    "duration_ms": 2500,
    "results": {
      "total_patterns_found": 5,
      "direct_syscalls": 3,
      "syswhispers_detected": 2,
      "memory_regions_scanned": 15,
      "bytes_scanned": 15728640
    },
    "detections": [
      {
        "address": "0x401000",
        "pattern": "direct_syscall_x64",
        "syscall_number": 24,
        "confidence": 0.92
      }
    ],
    "status": "completed"
  }
}
```

---

## GET /syscalls/patterns

Получить список известных паттернов syscalls.

### Example Response

```json
{
  "data": {
    "patterns": [
      {
        "name": "direct_syscall_x64",
        "description": "Direct x64 syscall pattern",
        "opcodes": "4C8BD1B8????????0F05",
        "mask": "FFFFFF00000000FFFF",
        "threat_level": "HIGH",
        "bypass_risk": "MEDIUM"
      },
      {
        "name": "syswhispers_template",
        "description": "SysWhispers2/3 template",
        "opcodes": "4C8BD1B8????????F604250803FE7F01",
        "mask": "FFFFFF00000000FFFFFFFFFFFFFFFF",
        "threat_level": "CRITICAL",
        "bypass_risk": "HIGH"
      }
    ],
    "total": 15
  }
}
```

---

## POST /syscalls/monitoring

Управление мониторингом syscalls.

### Request Body

```json
{
  "action": "start",
  "settings": {
    "monitor_all_processes": true,
    "whitelist": ["explorer.exe", "svchost.exe"],
    "log_level": "INFO",
    "real_time_alerts": true
  }
}
```

### Actions

| Action | Description |
|--------|-------------|
| `start` | Запустить мониторинг |
| `stop` | Остановить мониторинг |
| `restart` | Перезапустить с новыми настройками |
| `pause` | Приостановить мониторинг |
| `resume` | Возобновить мониторинг |

### Example Response

```json
{
  "data": {
    "action": "start",
    "status": "active",
    "monitoring_started": "2023-11-06T12:00:00Z",
    "processes_monitored": 125,
    "settings": {
      "monitor_all_processes": true,
      "whitelist_size": 2,
      "log_level": "INFO",
      "real_time_alerts": true
    }
  }
}
```

---

## Error Responses

### Process Access Denied
```json
{
  "error": {
    "code": "PROCESS_ACCESS_DENIED",
    "message": "Cannot access process memory",
    "details": {
      "pid": 1234,
      "required_privilege": "SeDebugPrivilege"
    }
  }
}
```

### Monitoring Not Active
```json
{
  "error": {
    "code": "MONITORING_NOT_ACTIVE",
    "message": "Syscall monitoring is not currently active",
    "details": {
      "status": "stopped",
      "last_active": 1699123456
    }
  }
}
```