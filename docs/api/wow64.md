# WoW64 API

Мониторинг WoW64 процессов и детекция Heaven's Gate техники.

## GET /wow64

Получить информацию о WoW64 процессах и переходах.

### Query Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `transitions_only` | boolean | false | Только процессы с переходами |
| `pid` | integer | - | Фильтр по Process ID |
| `since` | integer | - | Unix timestamp (фильтр по времени) |
| `limit` | integer | 100 | Максимальное количество результатов |
| `offset` | integer | 0 | Смещение для пагинации |

### Example Request

```bash
curl -H "Authorization: Bearer your-token" \
     "http://127.0.0.1:8080/api/wow64?transitions_only=true"
```

### Example Response

```json
{
  "data": {
    "wow64_processes": [
      {
        "pid": 1234,
        "name": "malware32.exe",
        "parent_pid": 1000,
        "is_wow64": true,
        "create_time": 1699123456,
        "peb32_address": "0x002F0000",
        "peb64_address": "0x00000000002F0000",
        "x64_regions": [
          {
            "base": "0x7FF800000000",
            "size": 4096,
            "protection": "PAGE_EXECUTE_READ",
            "contains_code": true
          }
        ],
        "transitions": [
          {
            "id": "trans_001",
            "from_cs": "0x23",
            "to_cs": "0x33",
            "from_address": "0x401000",
            "to_address": "0x7FF800001000",
            "pattern": "far_jump_x64",
            "confidence": 0.94,
            "timestamp": 1699123456
          }
        ],
        "threat_level": "HIGH",
        "detection_count": 5
      }
    ],
    "pagination": {
      "total": 25,
      "limit": 100,
      "offset": 0,
      "has_more": false
    }
  },
  "meta": {
    "total_wow64_processes": 25,
    "processes_with_transitions": 3,
    "monitoring_active": true,
    "timestamp": 1699123456
  }
}
```

---

## GET /wow64/{pid}

Детальная информация о конкретном WoW64 процессе.

### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `pid` | integer | Process ID |

### Example Request

```bash
curl -H "Authorization: Bearer your-token" \
     "http://127.0.0.1:8080/api/wow64/1234"
```

### Example Response

```json
{
  "data": {
    "pid": 1234,
    "name": "malware32.exe",
    "is_wow64": true,
    "architecture": "x86_on_x64",
    "peb_info": {
      "peb32_address": "0x002F0000",
      "peb64_address": "0x00000000002F0000",
      "image_base_32": "0x00400000",
      "image_base_64": null
    },
    "wow64_cpu": {
      "dll_base": "0x77550000",
      "context_switch_count": 147,
      "x64_execution_time_ms": 1250
    },
    "x64_code_regions": [
      {
        "base": "0x7FF800000000",
        "size": 4096,
        "protection": "PAGE_EXECUTE_READ",
        "allocation_type": "PRIVATE",
        "contains_code": true,
        "instruction_analysis": {
          "x64_instructions": 89,
          "x86_instructions": 11,
          "ratio": 0.89,
          "suspicious_patterns": ["rex_prefix_abundance"]
        }
      }
    ],
    "segment_transitions": [
      {
        "id": "trans_001",
        "from_cs": "0x23",
        "to_cs": "0x33",
        "from_address": "0x401000",
        "to_address": "0x7FF800001000",
        "transition_type": "far_jump",
        "pattern": "push_retf_x64",
        "disassembly": [
          {
            "address": "0x401000",
            "instruction": "push 0x33",
            "bytes": "6A33"
          },
          {
            "address": "0x401002",
            "instruction": "call $+5",
            "bytes": "E800000000"
          },
          {
            "address": "0x401007",
            "instruction": "add [rsp], 5",
            "bytes": "83042405"
          },
          {
            "address": "0x40100B",
            "instruction": "retf",
            "bytes": "CB"
          }
        ],
        "confidence": 0.94,
        "timestamp": 1699123456,
        "validated": true,
        "threat_indicators": [
          "manual_cs_switch",
          "x64_shellcode_execution"
        ]
      }
    ],
    "hooks_detected": [
      {
        "function": "Wow64SystemServiceCall",
        "original_address": "0x77551000",
        "hooked_address": "0x401050",
        "hook_type": "inline",
        "confidence": 0.87
      }
    ],
    "threat_assessment": {
      "overall_score": 0.94,
      "threat_level": "CRITICAL",
      "indicators": [
        "manual_segment_switching",
        "x64_code_injection",
        "wow64_hook_bypass"
      ],
      "recommendations": [
        "terminate_process",
        "create_memory_dump",
        "block_parent_process"
      ]
    }
  }
}
```

---

## POST /wow64/scan

Запустить сканирование для поиска Heaven's Gate активности.

### Request Body

```json
{
  "pid": 1234,
  "scan_depth": "deep",
  "check_all_regions": true,
  "analyze_transitions": true,
  "create_report": true
}
```

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `pid` | integer | - | Process ID (опционально, для всех WoW64 если не указан) |
| `scan_depth` | string | "normal" | quick, normal, deep, forensic |
| `check_all_regions` | boolean | false | Сканировать все регионы памяти |
| `analyze_transitions` | boolean | true | Анализировать переходы сегментов |
| `create_report` | boolean | false | Создать детальный отчет |

### Example Request

```bash
curl -X POST \
     -H "Authorization: Bearer your-token" \
     -H "Content-Type: application/json" \
     -d '{"scan_depth": "deep", "analyze_transitions": true}' \
     "http://127.0.0.1:8080/api/wow64/scan"
```

### Example Response

```json
{
  "data": {
    "scan_id": "wow64_scan_001",
    "start_time": "2023-11-06T12:00:00Z",
    "end_time": "2023-11-06T12:00:45Z",
    "duration_ms": 45000,
    "processes_scanned": 25,
    "results": {
      "total_wow64_processes": 25,
      "suspicious_processes": 3,
      "heavens_gate_detected": 1,
      "manual_transitions": 5,
      "hook_bypasses": 2
    },
    "detections": [
      {
        "pid": 1234,
        "detection_type": "heavens_gate",
        "confidence": 0.94,
        "details": "Manual CS segment switching to x64 mode",
        "threat_level": "CRITICAL"
      }
    ],
    "report_path": "/reports/wow64_scan_001.json",
    "status": "completed"
  }
}
```

---

## GET /wow64/patterns

Получить список известных Heaven's Gate паттернов.

### Example Response

```json
{
  "data": {
    "patterns": [
      {
        "name": "far_jump_x64",
        "description": "Direct far jump to x64 segment",
        "opcodes": "EA????????3300",
        "mask": "FF00000000FF00",
        "cs_selector": "0x33",
        "threat_level": "CRITICAL"
      },
      {
        "name": "push_retf_x64",
        "description": "Push + retf technique",
        "opcodes": "6A33E8000000008304240?CB",
        "mask": "FFFFFFFFFFFFFFFFFFFF0FF",
        "cs_selector": "0x33",
        "threat_level": "HIGH"
      },
      {
        "name": "indirect_x64_call",
        "description": "Indirect call through x64 address",
        "opcodes": "48C7C0????????488BD1FFE0",
        "mask": "FFFFFF00000000FFFFFFFF",
        "cs_selector": "0x33",
        "threat_level": "HIGH"
      }
    ],
    "total": 8,
    "last_updated": 1699123456
  }
}
```

---

## GET /wow64/statistics

Получить статистику по WoW64 мониторингу.

### Query Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `hours` | integer | 24 | Период для статистики (часы) |

### Example Response

```json
{
  "data": {
    "timeframe": {
      "start": 1699123456,
      "end": 1699209856,
      "hours": 24
    },
    "wow64_activity": {
      "total_processes": 125,
      "max_concurrent": 45,
      "avg_concurrent": 25,
      "new_processes": 78,
      "terminated_processes": 53
    },
    "heavens_gate_detections": {
      "total": 15,
      "by_pattern": {
        "far_jump_x64": 8,
        "push_retf_x64": 5,
        "indirect_x64_call": 2
      },
      "by_confidence": {
        "high": 12,
        "medium": 3,
        "low": 0
      }
    },
    "segment_transitions": {
      "total": 247,
      "legitimate": 232,
      "suspicious": 15,
      "avg_per_process": 9.8
    },
    "performance": {
      "scan_latency_ms": 1.2,
      "memory_overhead_mb": 15,
      "cpu_usage_percent": 0.5,
      "false_positive_rate": 0.02
    }
  }
}
```

---

## POST /wow64/monitoring

Управление мониторингом WoW64.

### Request Body

```json
{
  "action": "start",
  "settings": {
    "monitor_all_wow64": true,
    "real_time_analysis": true,
    "auto_scan_new_processes": true,
    "alert_threshold": 0.8,
    "max_transitions_per_process": 100
  }
}
```

### Example Response

```json
{
  "data": {
    "action": "start",
    "status": "active",
    "monitoring_started": "2023-11-06T12:00:00Z",
    "wow64_processes_monitored": 25,
    "settings_applied": {
      "monitor_all_wow64": true,
      "real_time_analysis": true,
      "auto_scan_new_processes": true,
      "alert_threshold": 0.8,
      "max_transitions_per_process": 100
    }
  }
}
```

---

## Error Responses

### Not WoW64 Process
```json
{
  "error": {
    "code": "NOT_WOW64_PROCESS",
    "message": "Process is not running under WoW64",
    "details": {
      "pid": 1234,
      "architecture": "x64"
    }
  }
}
```

### Transition Analysis Failed
```json
{
  "error": {
    "code": "TRANSITION_ANALYSIS_FAILED",
    "message": "Failed to analyze segment transitions",
    "details": {
      "pid": 1234,
      "reason": "memory_access_denied",
      "required_privilege": "SeDebugPrivilege"
    }
  }
}
```