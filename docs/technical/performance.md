# Performance Tuning Guide

Optimize Process Guard for your environment.

## 📊 Performance Metrics

Target metrics:
- Detection latency: <1ms
- Memory usage: <60MB
- CPU usage: <3%
- Event throughput: >15,000/sec

## 🔧 Tuning Configuration

```toml
[performance]
max_memory_mb = 512
cpu_limit_percent = 5.0
event_buffer_size = 10000

[monitoring]
interval_ms = 100  # Adjust for performance vs responsiveness
```

## 📚 Related Documentation

- [Architecture](./architecture.md)
- [Configuration](../ops/config.md)

---

**Last Updated**: 2025-11-16
