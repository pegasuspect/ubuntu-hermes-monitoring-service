# hermes-sentinel

System-level security monitor for the [Hermes](https://github.com/…) agent
on Kubuntu. Watches Hermes logs, gateway state, and system auth logs for
unusual or unauthorized activity — and pushes **Signal alerts** to your
phone when something happens.

Runs as a **systemd user service with lingering enabled**, so it starts at
boot without anyone logging in, and needs no root.

## What it detects

| Detector | Source | Severity | Alert example |
|---|---|---|---|
| `hermes-logs` | `~/.hermes/logs/agent.log`, `errors.log`, `gateway.log` | **critical** | Gateway dropped a message from an **unauthorized user** (the exact `Dropping message from unauthorized user in active session` line the gateway emits) |
| | | warning | `Skipping auto-resume … no longer authorized` (removed allowlist user) |
| | | warning | Gateway **restart storm** (`(re)started N times in Xs`) |
| | | warning | Second gateway instance tried to start |
| | | warning → critical | **signal-cli unreachable** (repeated outages escalate) |
| `gateway-state` | `state/gateway.heartbeat`, `gateway-starts.log` | critical | Heartbeat PID is dead / heartbeat stale (gateway hung or killed) |
| | | warning | `gateway-starts.log` grows past the restart-storm threshold |
| `integrity` | `auth.json`, `.env`, `config.yaml`, `channel_directory.json` | **critical** | Any of these files was modified or deleted |
| `sessions` | `sessions/sessions.json` | warning | New Signal DM session from a number **not** in `allowed_users` |
| `system-auth` | `/var/log/auth.log` (journal fallback) | warning | **SSH brute force** (N failed logins in a window) |
| | | critical | A **new system user** was created |
| | | info | Successful SSH logins, sudo-to-root of interesting commands |

Dedup/cooldown/escalation are handled by a persistent ledger
(`~/.local/state/hermes-sentinel/state.json`): the same issue won't
re-alert for `cooldown` seconds, but repeats escalate to critical after
`escalate_after` occurrences.

## How alerts are delivered

Through the **same signal-cli JSON-RPC daemon** the Hermes gateway uses
(`http://127.0.0.1:8099`), so alerts arrive from your existing linked
Signal number — no extra registration. If signal-cli is temporarily down,
alerts are queued (with retry) until it's back.

## Quick start

```bash
# 1. verify all data sources and the signal daemon are reachable
python3 -m hermes_sentinel check

# 2. send a test alert to your Signal (config: signal.recipient)
python3 -m hermes_sentinel test-signal

# 3. install as a boot-time user service (enables lingering; no sudo)
./install.sh

# watch it
journalctl --user -u hermes-sentinel -f
tail -f ~/.local/state/hermes-sentinel/sentinel.log

# other commands
python3 -m hermes_sentinel run --dry-run   # foreground, log-only
python3 -m hermes_sentinel recent           # last tracked events
python3 -m hermes_sentinel reset            # clear the dedup ledger
```

## Configuration

**No personal data lives in this repo.** Signal numbers, alert recipients,
and trusted senders come from environment variables or a git-ignored local
config. Resolution order (first wins):

1. **Environment variables** (also settable in a `.env` file in the project
   root, or `~/.config/hermes-sentinel/env` for the systemd service):

   | Variable | Meaning |
   |---|---|
   | `SIGNAL_ACCOUNT` | linked Signal number (the signal-cli account) |
   | `SIGNAL_RECIPIENT` | where alerts go: phone, or `group:<base64>` |
   | `SIGNAL_ALLOWED_USERS` | comma-separated trusted senders |
   | `SIGNAL_HTTP_URL` | signal-cli daemon URL (default `http://127.0.0.1:8099`) |
   | `NOTIFY_ON` | e.g. `warning,critical` (add `info` for SSH chatter) |
   | `AUTH_LOG_PATH` | override the system auth-log path |

2. **`config/sentinel.local.yaml`** — git-ignored; copy from
   `config/sentinel.local.yaml.example` and fill in your values.
3. **`config/sentinel.yaml`** — committed template with non-personal
   tuning (intervals, thresholds, detector toggles).

Getting started:

```bash
cp .env.example .env                  # then edit .env with your number
# or: cp config/sentinel.local.yaml.example config/sentinel.local.yaml
python3 -m hermes_sentinel check      # verifies the values are picked up
```

Other notable settings (in `config/sentinel.yaml`):

- `cooldown`, `escalate_after` — alert dedup tuning.
- `quiet_hours` — optional; mute info-level alerts at night.
- `detectors.*` — toggle each detector on/off.

## Architecture

```
┌────────────────┐   events   ┌──────────┐   dedup/cooldown/escalate   ┌────────────┐
│ detectors (5x)  ├──────────►│  ledger  ├────────────────────────────►│ signal-cli │
│ log tailers &   │           │ (json)   │                             │ JSON-RPC   │
│ state pollers   │           └──────────┘                             │ :8099      │
└────────────────┘                                                    └─────┬──────┘
                                                                            ▼
                                                                   📱 Signal alert
```

- **Log tailers** (`hermes_sentinel/tailer.py`) are rotation-safe
  (inode + offset tracking, truncation and rotate detection) and skip
  backlog on first sight — no startup alert storm.
- **Detectors** run in small dedicated threads and push events onto a
  bounded queue; a consumer applies the ledger; a dispatcher delivers
  Signal messages with retry and requeue-on-failure.
- **No third-party runtime deps** — pure Python 3.12 stdlib (PyYAML is
  used when present for the config, with a built-in mini-parser fallback).
- The service is a *user* unit (`systemd/hermes-sentinel.service`)
  started at boot via `loginctl enable-linger`, so it works without login
  and without any root access.

## Tests

```bash
python3 -m pytest tests/ -q
```

30 tests cover the ledger semantics (cooldown, escalation, persistence),
tailer edge cases (rotation, truncation, partial lines), every detector
against realistic log lines from this machine, the Signal notifier
(payload shape, result validation, retry), and config parsing.

## Security notes

- The sentinel only *reads* logs and state; it never writes to `~/.hermes`.
- Its own state lives in `~/.local/state/hermes-sentinel/` (0600 file
  perms recommended: `chmod 600 state.json`).
- Alerts are sent only to the configured `signal.recipient` — if your
  Signal is compromised, treat the machine as compromised too (and vice
  versa: integrity alerts tell you when hermes' own credentials, e.g.
  `auth.json` / `.env`, were touched).