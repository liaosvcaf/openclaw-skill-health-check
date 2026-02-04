#!/usr/bin/env bash
# OpenClaw Comprehensive Health Check
# Generates a structured report covering all subsystems
set -euo pipefail

OPENCLAW_DIR="${OPENCLAW_DIR:-$HOME/.openclaw}"
LOG_DIR="$OPENCLAW_DIR/logs"
SESSION_DIR="$OPENCLAW_DIR/agents/main/sessions"
OPENCLAW_LOG="/tmp/openclaw/openclaw-$(date +%Y-%m-%d).log"

# Colors (disabled if not a terminal)
if [ -t 1 ]; then
  OK="\033[32mOK\033[0m"; WARN="\033[33mWARN\033[0m"; FAIL="\033[31mFAIL\033[0m"; BOLD="\033[1m"; RESET="\033[0m"
else
  OK="OK"; WARN="WARN"; FAIL="FAIL"; BOLD=""; RESET=""
fi

issues=0
warnings=0

section() { echo ""; echo "=== $1 ==="; }
ok()      { echo "  [$OK] $1"; }
warn()    { echo "  [$WARN] $1"; warnings=$((warnings + 1)); }
fail()    { echo "  [$FAIL] $1"; issues=$((issues + 1)); }

# ── 1. Gateway Process ──
section "Gateway Process"

GW_STATUS=$(openclaw gateway status 2>/dev/null || echo "")
GW_PID=$(echo "$GW_STATUS" | grep -oE 'pid [0-9]+' | grep -oE '[0-9]+' | head -1 || true)
if [ -n "$GW_PID" ] && ps -p "$GW_PID" > /dev/null 2>&1; then
  GW_UPTIME=$(ps -p "$GW_PID" -o etime= 2>/dev/null | xargs)
  ok "Gateway running (PID $GW_PID, uptime: $GW_UPTIME)"
else
  # Fallback: try pgrep
  GW_PID=$(pgrep -f "openclaw.*gateway\|openclaw/dist/index.js.*gateway" 2>/dev/null | head -1 || true)
  if [ -n "$GW_PID" ]; then
    GW_UPTIME=$(ps -p "$GW_PID" -o etime= 2>/dev/null | xargs)
    ok "Gateway running (PID $GW_PID, uptime: $GW_UPTIME)"
  else
    fail "Gateway process not found"
  fi
fi

# Version
OC_VERSION=$(openclaw --version 2>/dev/null || echo "unknown")
echo "  Version: $OC_VERSION"

# ── 2. Gateway Logs Health ──
section "Recent Errors (last 1 hour)"

if [ -f "$LOG_DIR/gateway.err.log" ]; then
  ONE_HOUR_AGO=$(date -u -v-1H +%Y-%m-%dT%H:%M 2>/dev/null || date -u -d '1 hour ago' +%Y-%m-%dT%H:%M 2>/dev/null || echo "")
  if [ -n "$ONE_HOUR_AGO" ]; then
    # Extract recent lines by matching timestamp prefix
    RECENT_FILE=$(mktemp)
    grep -E "^[0-9]{4}-[0-9]{2}-[0-9]{2}T" "$LOG_DIR/gateway.err.log" 2>/dev/null | \
      awk -F'T' -v since="$ONE_HOUR_AGO" '{ts=$1"T"substr($2,1,5)} ts >= since' > "$RECENT_FILE" || true

    ERR_COUNT=$(wc -l < "$RECENT_FILE" | xargs)
    if [ "$ERR_COUNT" -gt 10 ]; then
      fail "$ERR_COUNT errors in the last hour"
    elif [ "$ERR_COUNT" -gt 0 ]; then
      warn "$ERR_COUNT errors in the last hour"
    else
      ok "No errors in the last hour"
    fi

    count_pattern() { local n; n=$(grep -cE "$1" "$RECENT_FILE" 2>/dev/null) || true; echo "${n:-0}"; }

    CREDIT_ERRS=$(count_pattern "402.*credits|billing|quota")
    if [ "$CREDIT_ERRS" -gt 0 ]; then
      fail "Provider billing/credits errors detected ($CREDIT_ERRS occurrences)"
    fi

    RATE_ERRS=$(count_pattern "cooldown|rate_limit")
    if [ "$RATE_ERRS" -gt 0 ]; then
      warn "Provider rate limiting detected ($RATE_ERRS occurrences)"
    fi

    OVERFLOW_ERRS=$(count_pattern "Context overflow|prompt too large|context_length_exceeded")
    if [ "$OVERFLOW_ERRS" -gt 0 ]; then
      fail "Context overflow errors detected ($OVERFLOW_ERRS occurrences)"
    fi

    AGENT_FAILS=$(count_pattern "Embedded agent failed before reply")
    if [ "$AGENT_FAILS" -gt 0 ]; then
      fail "Agent failures: $AGENT_FAILS runs failed before reply"
    fi

    rm -f "$RECENT_FILE"
  else
    warn "Cannot determine time range for error filtering"
  fi
else
  warn "No error log found at $LOG_DIR/gateway.err.log"
fi

# ── 3. Provider Status ──
section "Provider Status"

if [ -f "$LOG_DIR/gateway.err.log" ]; then
  # Check each provider for recent failures
  for provider in anthropic openrouter openai google; do
    RECENT=$(tail -200 "$LOG_DIR/gateway.err.log" | grep -i "$provider" | tail -1 || true)
    if echo "$RECENT" | grep -qi "402\|billing\|quota\|credits"; then
      fail "$provider: billing/credits issue"
    elif echo "$RECENT" | grep -qi "cooldown\|rate_limit"; then
      warn "$provider: rate limited (may be transient)"
    elif echo "$RECENT" | grep -qi "401\|auth\|invalid.*key"; then
      fail "$provider: authentication error"
    elif [ -n "$RECENT" ]; then
      warn "$provider: recent error detected"
    else
      ok "$provider: no recent errors"
    fi
  done
fi

# ── 4. Channel Health ──
section "Channels"

if [ -f "$LOG_DIR/gateway.log" ]; then
  # Telegram
  TG_STATUS=$(grep -i "telegram.*starting\|telegram.*provider" "$LOG_DIR/gateway.log" | tail -1 || true)
  if [ -n "$TG_STATUS" ]; then
    ok "Telegram: configured"
  else
    echo "  Telegram: not configured"
  fi

  # WebSocket/Webchat
  WS_CONN=$(grep "webchat connected" "$LOG_DIR/gateway.log" | tail -1 || true)
  WS_DISC=$(grep "webchat disconnected" "$LOG_DIR/gateway.log" | tail -1 || true)
  if [ -n "$WS_CONN" ]; then
    WS_TS=$(echo "$WS_CONN" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}' || echo "unknown")
    ok "Webchat: last connected at $WS_TS"
  else
    warn "Webchat: no connections found in current log"
  fi
fi

# ── 5. Cron/Heartbeat Status ──
section "Cron & Heartbeat"

CRON_STORE="$OPENCLAW_DIR/cron/jobs.json"
if [ -f "$CRON_STORE" ]; then
  TOTAL_JOBS=$(python3 -c "import json; d=json.load(open('$CRON_STORE')); print(len(d.get('jobs',[])))" 2>/dev/null || echo "?")
  FAILED_JOBS=$(python3 -c "
import json
d=json.load(open('$CRON_STORE'))
failed = [j for j in d.get('jobs',[]) if j.get('state',{}).get('lastStatus')=='error']
for j in failed:
    name = j.get('name','unnamed')
    err = j.get('state',{}).get('lastError','unknown')[:80]
    consec = j.get('state',{}).get('consecutiveFailures',0)
    print(f'{name}: {consec} consecutive failures, last: {err}')
" 2>/dev/null || echo "")

  echo "  Total cron jobs: $TOTAL_JOBS"
  if [ -n "$FAILED_JOBS" ]; then
    while IFS= read -r line; do
      fail "Cron: $line"
    done <<< "$FAILED_JOBS"
  else
    ok "All cron jobs healthy"
  fi
else
  echo "  No cron jobs configured"
fi

# Heartbeat last run
if [ -f "$OPENCLAW_LOG" ]; then
  LAST_HB=$(grep "heartbeat" "$OPENCLAW_LOG" 2>/dev/null | tail -1 || true)
  if [ -n "$LAST_HB" ]; then
    HB_TS=$(echo "$LAST_HB" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}' | head -1 || echo "unknown")
    ok "Last heartbeat activity: $HB_TS"
  fi
fi

# ── 6. Sessions ──
section "Sessions"

if [ -d "$SESSION_DIR" ]; then
  TOTAL_SESSIONS=$(ls "$SESSION_DIR"/*.jsonl 2>/dev/null | wc -l | xargs)
  ACTIVE_SESSION=$(ls -t "$SESSION_DIR"/*.jsonl 2>/dev/null | head -1)
  echo "  Total session files: $TOTAL_SESSIONS"
  if [ -n "$ACTIVE_SESSION" ]; then
    SESS_SIZE=$(du -h "$ACTIVE_SESSION" 2>/dev/null | cut -f1 | xargs)
    SESS_LINES=$(wc -l < "$ACTIVE_SESSION" 2>/dev/null | xargs)
    echo "  Active session: $(basename "$ACTIVE_SESSION")"
    echo "  Active session size: $SESS_SIZE ($SESS_LINES entries)"
    if [ "$SESS_LINES" -gt 500 ]; then
      warn "Active session is large ($SESS_LINES entries) -- context may be heavy"
    fi
  fi
fi

# ── 7. Disk & Storage ──
section "Storage"

OC_SIZE=$(du -sh "$OPENCLAW_DIR" 2>/dev/null | cut -f1 | xargs || echo "unknown")
LOGS_SIZE=$(du -sh "$LOG_DIR" 2>/dev/null | cut -f1 | xargs || echo "unknown")
SESSIONS_SIZE=$(du -sh "$SESSION_DIR" 2>/dev/null | cut -f1 | xargs || echo "unknown")
echo "  OpenClaw total: $OC_SIZE"
echo "  Logs: $LOGS_SIZE"
echo "  Sessions: $SESSIONS_SIZE"

DISK_AVAIL=$(df -h "$OPENCLAW_DIR" 2>/dev/null | tail -1 | awk '{print $4}' || echo "unknown")
echo "  Disk available: $DISK_AVAIL"

# ── 8. External Services ──
section "External Services"

# Mirror daemon
MIRROR_PID=$(pgrep -f "mirror_daemon" 2>/dev/null | head -1 || true)
if [ -n "$MIRROR_PID" ]; then
  ok "Mirror daemon running (PID $MIRROR_PID)"
else
  MIRROR_PLIST=$(launchctl list com.openclaw.mirror-daemon 2>/dev/null || true)
  if [ -n "$MIRROR_PLIST" ]; then
    warn "Mirror daemon registered in launchd but not running"
  else
    echo "  Mirror daemon: not configured"
  fi
fi

# ── 9. Config Sanity ──
section "Configuration"

CONFIG_FILE="$OPENCLAW_DIR/openclaw.json"
# Also check yaml
if [ ! -f "$CONFIG_FILE" ]; then
  CONFIG_FILE="$OPENCLAW_DIR/config.yaml"
fi
if [ -f "$CONFIG_FILE" ]; then
  ok "Config file exists"

  # Parse config (supports both JSON and YAML)
  if echo "$CONFIG_FILE" | grep -q "\.json$"; then
    CTX_TOKENS=$(python3 -c "
import json
with open('$CONFIG_FILE') as f:
    c = json.load(f)
    ct = c.get('agents',{}).get('defaults',{}).get('contextTokens','')
    if ct: print(ct)
" 2>/dev/null || echo "")
    COMPACT_MODE=$(python3 -c "
import json
with open('$CONFIG_FILE') as f:
    c = json.load(f)
    m = c.get('agents',{}).get('defaults',{}).get('compaction',{}).get('mode','')
    if m: print(m)
" 2>/dev/null || echo "")
  else
    CTX_TOKENS=$(grep -i "contextTokens" "$CONFIG_FILE" 2>/dev/null | grep -oE '[0-9]+' | head -1 || echo "")
    COMPACT_MODE=$(grep -A1 "compaction" "$CONFIG_FILE" 2>/dev/null | grep "mode" | awk '{print $2}' || echo "")
  fi

  if [ -n "$CTX_TOKENS" ]; then
    echo "  contextTokens: $CTX_TOKENS"
    if [ "$CTX_TOKENS" -lt 80000 ]; then
      warn "contextTokens ($CTX_TOKENS) is low -- risk of compaction lockout"
    elif [ "$CTX_TOKENS" -gt 180000 ]; then
      warn "contextTokens ($CTX_TOKENS) is very high -- risk of context overflow"
    else
      ok "contextTokens in reasonable range"
    fi
  fi

  if [ -n "$COMPACT_MODE" ]; then
    echo "  compaction mode: $COMPACT_MODE"
    if [ "$COMPACT_MODE" = "safeguard" ]; then
      warn "Compaction mode 'safeguard' may cause overflow -- consider 'default'"
    fi
  fi
else
  fail "No config file found at $CONFIG_FILE"
fi

# ── 10. Network ──
section "Network"

if curl -s --max-time 5 https://api.anthropic.com > /dev/null 2>&1; then
  ok "Anthropic API reachable"
else
  fail "Cannot reach Anthropic API"
fi

if curl -s --max-time 5 https://openrouter.ai > /dev/null 2>&1; then
  ok "OpenRouter reachable"
else
  warn "Cannot reach OpenRouter"
fi

# ── Summary ──
section "Summary"
echo ""
if [ "$issues" -eq 0 ] && [ "$warnings" -eq 0 ]; then
  echo "  ${BOLD}All checks passed. System is healthy.${RESET}"
elif [ "$issues" -eq 0 ]; then
  echo "  ${BOLD}$warnings warning(s), no critical issues.${RESET}"
else
  echo "  ${BOLD}$issues critical issue(s), $warnings warning(s) found.${RESET}"
fi
echo ""
echo "Report generated: $(date)"
