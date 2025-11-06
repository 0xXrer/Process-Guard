# Processes API

Управление и мониторинг процессов.

## GET /processes

Список всех мониторизируемых процессов.

### Query Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `suspicious` | boolean | false | Только подозрительные процессы |
| `limit` | integer | 100 | Максимальное количество результатов |
| `offset` | integer | 0 | Смещение для пагинации |
| `sort` | string | "pid" | Сортировка: pid, name, risk_score, create_time |
| `order` | string | "asc" | Порядок: asc, desc |
| `filter` | string | - | Фильтр по имени процесса |

### Example Request

```bash
curl -H "Authorization: Bearer your-token" \
     "http://127.0.0.1:8080/api/processes?suspicious=true&limit=50"
```

### Example Response

```json
{
  "data": {
    "processes": [
      {
        "pid": 1234,
        "name": "explorer.exe",
        "parent_pid": 1000,
        "create_time": 1699123456,
        "image_base": "0x7ff6c2340000",
        "entry_point": "0x7ff6c2341000",
        "risk_score": 0.0,
        "status": "CLEAN",
        "detection_count": 0,
        "last_scan": 1699123456
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
    "suspicious_count": 2,
    "total_count": 150,
    "timestamp": 1699123456
  }
}
```

### Status Values

| Status | Description |
|--------|-------------|
| `CLEAN` | Процесс чистый |
| `SUSPICIOUS` | Подозрительная активность |
| `MALICIOUS` | Обнаружены инъекции |
| `TERMINATED` | Процесс завершен |
| `SCANNING` | Идет сканирование |

---

## GET /processes/{pid}

Детальная информация о конкретном процессе.

### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `pid` | integer | Process ID |

### Example Request

```bash
curl -H "Authorization: Bearer your-token" \
     "http://127.0.0.1:8080/api/processes/1234"
```

### Example Response

```json
{
  "data": {
    "pid": 1234,
    "name": "explorer.exe",
    "parent_pid": 1000,
    "create_time": 1699123456,
    "image_base": "0x7ff6c2340000",
    "entry_point": "0x7ff6c2341000",
    "risk_score": 0.0,
    "status": "CLEAN",
    "detections": [],
    "memory_regions": [
      {
        "base": "0x7ff6c2340000",
        "size": 1048576,
        "protection": "PAGE_EXECUTE_READ",
        "type": "IMAGE"
      }
    ],
    "threads": [
      {
        "tid": 5678,
        "start_address": "0x7ff6c2341000",
        "state": "Running"
      }
    ],
    "modules": [
      {
        "name": "explorer.exe",
        "base": "0x7ff6c2340000",
        "size": 1048576,
        "path": "C:\\Windows\\explorer.exe"
      }
    ]
  }
}
```

---

## POST /scan/{pid}

Запустить сканирование конкретного процесса.

### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `pid` | integer | Process ID |

### Request Body

```json
{
  "techniques": [
    "ProcessHollowing",
    "ThreadHijacking",
    "ProcessDoppelganging",
    "DirectSyscalls",
    "HeavensGate"
  ],
  "deep_scan": true,
  "memory_dump": false,
  "timeout_seconds": 30
}
```

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `techniques` | array | all | Список техник для проверки |
| `deep_scan` | boolean | false | Глубокое сканирование памяти |
| `memory_dump` | boolean | false | Создать дамп памяти |
| `timeout_seconds` | integer | 30 | Таймаут сканирования |

### Example Request

```bash
curl -X POST \
     -H "Authorization: Bearer your-token" \
     -H "Content-Type: application/json" \
     -d '{"deep_scan": true, "techniques": ["DirectSyscalls"]}' \
     "http://127.0.0.1:8080/api/scan/1234"
```

### Example Response

```json
{
  "data": {
    "pid": 1234,
    "scan_id": "scan_001",
    "start_time": "2023-11-06T12:00:00Z",
    "end_time": "2023-11-06T12:00:15Z",
    "duration_ms": 15000,
    "detections": [
      {
        "technique": "DirectSyscalls",
        "confidence": 0.89,
        "details": "Direct syscalls detected at 0x401000",
        "addresses": ["0x401000", "0x401050"],
        "timestamp": 1699123456
      }
    ],
    "risk_score": 0.89,
    "status": "MALICIOUS",
    "memory_dump_path": "/tmp/process_1234_dump.bin"
  }
}
```

---

## DELETE /processes/{pid}

Завершить подозрительный процесс.

### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `pid` | integer | Process ID |

### Request Body

```json
{
  "force": true,
  "reason": "Direct syscalls detected",
  "create_dump": false
}
```

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `force` | boolean | false | Принудительное завершение |
| `reason` | string | - | Причина завершения |
| `create_dump` | boolean | false | Создать дамп перед завершением |

### Example Request

```bash
curl -X DELETE \
     -H "Authorization: Bearer your-token" \
     -H "Content-Type: application/json" \
     -d '{"force": true, "reason": "Malicious activity detected"}' \
     "http://127.0.0.1:8080/api/processes/1234"
```

### Example Response

```json
{
  "data": {
    "pid": 1234,
    "terminated": true,
    "timestamp": 1699123456,
    "reason": "Malicious activity detected",
    "dump_created": false
  }
}
```

---

## Error Responses

### Process Not Found
```json
{
  "error": {
    "code": "PROCESS_NOT_FOUND",
    "message": "Process with PID 1234 not found",
    "details": {
      "pid": 1234
    }
  }
}
```

### Access Denied
```json
{
  "error": {
    "code": "ACCESS_DENIED",
    "message": "Insufficient privileges to access process",
    "details": {
      "pid": 1234,
      "required_privilege": "SeDebugPrivilege"
    }
  }
}
```

### Scan In Progress
```json
{
  "error": {
    "code": "SCAN_IN_PROGRESS",
    "message": "Process is already being scanned",
    "details": {
      "pid": 1234,
      "scan_id": "scan_001",
      "started_at": 1699123456
    }
  }
}
```