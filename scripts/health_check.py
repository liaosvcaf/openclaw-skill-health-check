#!/usr/bin/env python3
"""OpenClaw Comprehensive Health Check — 10-subsystem diagnostic report."""

import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

OPENCLAW_DIR = Path(os.environ.get("OPENCLAW_DIR", Path.home() / ".openclaw"))
LOG_DIR = OPENCLAW_DIR / "logs"
SESSION_DIR = OPENCLAW_DIR / "agents" / "main" / "sessions"
TODAY = datetime.now().strftime("%Y-%m-%d")
OPENCLAW_LOG = Path("/tmp/openclaw") / f"openclaw-{TODAY}.log"

issues = 0
warnings = 0


def section(name):
    print(f"\n=== {name} ===")


def ok(msg):
    print(f"  [OK] {msg}")


def warn(msg):
    global warnings
    print(f"  [WARN] {msg}")
    warnings += 1


def fail(msg):
    global issues
    print(f"  [FAIL] {msg}")
    issues += 1


def run(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.returncode
    except Exception:
        return "", 1


def count_in_lines(lines, pattern):
    regex = re.compile(pattern, re.IGNORECASE)
    return sum(1 for l in lines if regex.search(l))


def get_recent_errors(log_path, minutes=60):
    """Get log lines from the last N minutes based on ISO timestamps."""
    if not log_path.exists():
        return []
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M")
    lines = []
    try:
        with open(log_path, "r", errors="replace") as f:
            for line in f:
                m = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2})", line)
                if m and m.group(1) >= cutoff:
                    lines.append(line)
    except Exception:
        pass
    return lines


# ── 1. Gateway Process ──
section("Gateway Process")

gw_out, _ = run("openclaw gateway status 2>/dev/null")
pid_match = re.search(r"pid (\d+)", gw_out)
gw_pid = pid_match.group(1) if pid_match else None

if gw_pid:
    ps_out, _ = run(f"ps -p {gw_pid} -o etime=")
    uptime = ps_out.strip() if ps_out else "unknown"
    ok(f"Gateway running (PID {gw_pid}, uptime: {uptime})")
else:
    # Fallback
    pgrep_out, _ = run("pgrep -f 'openclaw.*gateway|openclaw/dist/index.js.*gateway'")
    if pgrep_out:
        gw_pid = pgrep_out.split()[0]
        ps_out, _ = run(f"ps -p {gw_pid} -o etime=")
        ok(f"Gateway running (PID {gw_pid}, uptime: {ps_out.strip()})")
    else:
        fail("Gateway process not found")

version, _ = run("openclaw --version 2>/dev/null")
print(f"  Version: {version or 'unknown'}")


# ── 2. Recent Errors ──
section("Recent Errors (last 1 hour)")

err_log = LOG_DIR / "gateway.err.log"
recent = get_recent_errors(err_log, 60)

if recent:
    err_count = len(recent)
    if err_count > 10:
        fail(f"{err_count} errors in the last hour")
    elif err_count > 0:
        warn(f"{err_count} errors in the last hour")

    checks = [
        ("402.*credits|billing|quota", "Provider billing/credits errors", True),
        ("cooldown|rate_limit", "Provider rate limiting", False),
        ("Context overflow|prompt too large|context_length_exceeded", "Context overflow errors", True),
        ("Embedded agent failed before reply", "Agent run failures", True),
    ]
    for pattern, label, is_critical in checks:
        n = count_in_lines(recent, pattern)
        if n > 0:
            (fail if is_critical else warn)(f"{label} detected ({n} occurrences)")
elif err_log.exists():
    ok("No errors in the last hour")
else:
    warn(f"No error log found at {err_log}")


# ── 3. Provider Status ──
section("Provider Status")

if err_log.exists():
    try:
        with open(err_log, "r", errors="replace") as f:
            tail = f.readlines()[-200:]
    except Exception:
        tail = []

    for provider in ["anthropic", "openrouter", "openai", "google"]:
        provider_lines = [l for l in tail if provider in l.lower()]
        if not provider_lines:
            ok(f"{provider}: no recent errors")
            continue
        last = provider_lines[-1]
        if re.search(r"402|billing|quota|credits", last, re.I):
            fail(f"{provider}: billing/credits issue")
        elif re.search(r"cooldown|rate_limit", last, re.I):
            warn(f"{provider}: rate limited (may be transient)")
        elif re.search(r"401|auth|invalid.*key", last, re.I):
            fail(f"{provider}: authentication error")
        else:
            warn(f"{provider}: recent error detected")


# ── 4. Channel Health ──
section("Channels")

gw_log = LOG_DIR / "gateway.log"
if gw_log.exists():
    try:
        with open(gw_log, "r", errors="replace") as f:
            gw_lines = f.readlines()
    except Exception:
        gw_lines = []

    tg = [l for l in gw_lines if "telegram" in l.lower() and ("starting" in l.lower() or "provider" in l.lower())]
    if tg:
        ok("Telegram: configured")
    else:
        print("  Telegram: not configured")

    ws = [l for l in gw_lines if "webchat connected" in l]
    if ws:
        ts_match = re.search(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", ws[-1])
        ok(f"Webchat: last connected at {ts_match.group(1) if ts_match else 'unknown'}")
    else:
        warn("Webchat: no connections found in current log")


# ── 5. Cron & Heartbeat ──
section("Cron & Heartbeat")

cron_store = OPENCLAW_DIR / "cron" / "jobs.json"
if cron_store.exists():
    try:
        with open(cron_store) as f:
            cron_data = json.load(f)
        jobs = cron_data.get("jobs", [])
        print(f"  Total cron jobs: {len(jobs)}")
        failed_jobs = [j for j in jobs if j.get("state", {}).get("lastStatus") == "error"]
        if failed_jobs:
            for j in failed_jobs:
                name = j.get("name", "unnamed")
                err = (j.get("state", {}).get("lastError", "unknown") or "unknown")[:80]
                consec = j.get("state", {}).get("consecutiveFailures", 0)
                fail(f"Cron: {name}: {consec} consecutive failures, last: {err}")
        else:
            ok("All cron jobs healthy")
    except Exception as e:
        warn(f"Cannot parse cron store: {e}")
else:
    print("  No cron jobs configured")

if OPENCLAW_LOG.exists():
    try:
        with open(OPENCLAW_LOG, "r", errors="replace") as f:
            hb_lines = [l for l in f if "heartbeat" in l.lower()]
        if hb_lines:
            ts_match = re.search(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", hb_lines[-1])
            if ts_match:
                ok(f"Last heartbeat activity: {ts_match.group(1)}")
    except Exception:
        pass


# ── 6. Sessions ──
section("Sessions")

if SESSION_DIR.exists():
    sessions = sorted(SESSION_DIR.glob("*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)
    print(f"  Total session files: {len(sessions)}")
    if sessions:
        active = sessions[0]
        size_kb = active.stat().st_size / 1024
        with open(active, "r", errors="replace") as f:
            line_count = sum(1 for _ in f)
        print(f"  Active session: {active.name}")
        print(f"  Active session size: {size_kb:.0f}K ({line_count} entries)")
        if line_count > 500:
            warn(f"Active session is large ({line_count} entries) -- context may be heavy")


# ── 7. Storage ──
section("Storage")


def dir_size(path):
    if not path.exists():
        return "N/A"
    out, _ = run(f"du -sh '{path}' 2>/dev/null")
    return out.split()[0] if out else "unknown"


print(f"  OpenClaw total: {dir_size(OPENCLAW_DIR)}")
print(f"  Logs: {dir_size(LOG_DIR)}")
print(f"  Sessions: {dir_size(SESSION_DIR)}")

df_out, _ = run(f"df -h '{OPENCLAW_DIR}' 2>/dev/null")
if df_out:
    df_lines = df_out.strip().split("\n")
    if len(df_lines) >= 2:
        avail = df_lines[-1].split()[3] if len(df_lines[-1].split()) > 3 else "unknown"
        print(f"  Disk available: {avail}")


# ── 8. External Services ──
section("External Services")

mirror_pid, _ = run("pgrep -f mirror_daemon")
if mirror_pid:
    ok(f"Mirror daemon running (PID {mirror_pid.split()[0]})")
else:
    launchd_out, rc = run("launchctl list com.openclaw.mirror-daemon 2>/dev/null")
    if rc == 0 and launchd_out:
        warn("Mirror daemon registered in launchd but not running")
    else:
        print("  Mirror daemon: not configured")


# ── 9. Config Sanity ──
section("Configuration")

config_file = OPENCLAW_DIR / "openclaw.json"
if not config_file.exists():
    config_file = OPENCLAW_DIR / "config.yaml"

if config_file.exists():
    ok("Config file exists")
    try:
        if config_file.suffix == ".json":
            with open(config_file) as f:
                cfg = json.load(f)
            defaults = cfg.get("agents", {}).get("defaults", {})
            ctx_tokens = defaults.get("contextTokens")
            compact_mode = defaults.get("compaction", {}).get("mode")
        else:
            # YAML fallback: simple grep
            text = config_file.read_text()
            m = re.search(r"contextTokens:\s*(\d+)", text)
            ctx_tokens = int(m.group(1)) if m else None
            m = re.search(r"mode:\s*(\w+)", text)
            compact_mode = m.group(1) if m else None

        if ctx_tokens:
            print(f"  contextTokens: {ctx_tokens}")
            if ctx_tokens < 80000:
                warn(f"contextTokens ({ctx_tokens}) is low -- risk of compaction lockout")
            elif ctx_tokens > 180000:
                warn(f"contextTokens ({ctx_tokens}) is very high -- risk of context overflow")
            else:
                ok("contextTokens in reasonable range")

        if compact_mode:
            print(f"  compaction mode: {compact_mode}")
            if compact_mode == "safeguard":
                warn("Compaction mode 'safeguard' may cause overflow -- consider 'default'")
    except Exception as e:
        warn(f"Cannot parse config: {e}")
else:
    fail(f"No config file found")


# ── 10. Network ──
section("Network")

for name, url in [("Anthropic API", "https://api.anthropic.com"), ("OpenRouter", "https://openrouter.ai")]:
    _, rc = run(f"curl -s --max-time 5 '{url}' >/dev/null 2>&1")
    if rc == 0:
        ok(f"{name} reachable")
    else:
        (fail if "Anthropic" in name else warn)(f"Cannot reach {name}")


# ── Summary ──
section("Summary")
print()
if issues == 0 and warnings == 0:
    print("  All checks passed. System is healthy.")
elif issues == 0:
    print(f"  {warnings} warning(s), no critical issues.")
else:
    print(f"  {issues} critical issue(s), {warnings} warning(s) found.")
print()
print(f"Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z')}")
