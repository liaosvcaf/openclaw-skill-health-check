---
name: health-check
description: Comprehensive OpenClaw health check and diagnostics report. Run when the user asks about system health, status, diagnostics, "is everything working", "check health", "health report", "system status", or when troubleshooting failures. Covers gateway process, provider billing/auth, channels, cron/heartbeat failures, sessions, storage, config sanity, and network connectivity.
---

# Health Check

Run the comprehensive health check script:

```bash
python3 scripts/health_check.py
```

The script checks 10 subsystems and produces a structured report:

1. **Gateway Process** -- running, PID, uptime, version
2. **Recent Errors** -- last hour of gateway.err.log, categorized (billing, rate limits, overflow, agent failures)
3. **Provider Status** -- per-provider error detection (anthropic, openrouter, openai, google)
4. **Channel Health** -- Telegram, webchat connection status
5. **Cron & Heartbeat** -- job count, consecutive failures, last heartbeat activity
6. **Sessions** -- count, active session size (warns if large)
7. **Storage** -- disk usage for OpenClaw dir, logs, sessions, available disk
8. **External Services** -- mirror daemon, launchd services
9. **Configuration** -- contextTokens range, compaction mode sanity
10. **Network** -- API endpoint reachability

## Interpreting Results

- **FAIL** = critical issue requiring action (broken provider, overflow errors, process down)
- **WARN** = potential issue worth monitoring (rate limits, large sessions, low contextTokens)
- **OK** = subsystem healthy

## Customization

Set `OPENCLAW_DIR` environment variable if OpenClaw is installed in a non-default location:

```bash
OPENCLAW_DIR=/custom/path bash scripts/health_check.sh
```
