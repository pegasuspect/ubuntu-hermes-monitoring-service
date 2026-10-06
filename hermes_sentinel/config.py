"""Configuration loading (YAML via PyYAML, with a minimal fallback parser).

Values never live in this repo: anything personal (Signal account,
alert recipient, trusted senders) comes from environment variables or a
local (git-ignored) config file.

Resolution order (per key, first wins):
  1. Environment variable (see ENV_OVERRIDES below)
  2. Config file value
  3. Built-in DEFAULTS (placeholders only)

Config file search order:
  1. $HERMES_SENTINEL_CONFIG
  2. <project>/config/sentinel.local.yaml   (git-ignored; real values)
  3. <project>/config/sentinel.yaml         (template; placeholders)
  4. ~/.config/hermes-sentinel/sentinel.yaml
  5. /etc/hermes-sentinel/sentinel.yaml

An optional `.env` file in the project root (or $HERMES_SENTINEL_ENV) is
loaded first if present; real variables from the environment take
precedence over it.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

# Environment variables that override config-file values (dotted key).
ENV_OVERRIDES: Dict[str, str] = {
    "signal.account": "SIGNAL_ACCOUNT",
    "signal.recipient": "SIGNAL_RECIPIENT",
    "signal.http_url": "SIGNAL_HTTP_URL",
    "allowed_users": "SIGNAL_ALLOWED_USERS",
    "paths.auth_log": "AUTH_LOG_PATH",
    "notify_on": "NOTIFY_ON",
}

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DEFAULTS: Dict[str, Any] = {
    "poll_interval": 10.0,          # seconds between poller sweeps
    "tail_interval": 5.0,           # seconds between log-tail sweeps
    "max_events_per_sweep": 50,
    "escalate_after": 3,            # same fingerprint seen N times -> escalate severity
    "cooldown": 900.0,              # seconds before re-alerting the same fingerprint
    "aggregation_window": 20.0,     # batch events emitted this close together
    "heartbeat": {
        "expected_interval": 60.0,  # gateway heartbeat cadence (seconds)
        "stale_after": 180.0,       # stale if older than this
        "grace": 60.0,              # extra startup grace
    },
    "restart_storm": {
        "window": 300.0,            # rolling window for restart counting
        "threshold": 3,             # restarts within window to be "unusual"
    },
    "signal": {
        "http_url": "http://127.0.0.1:8099",
        # Personal values arrive via env/config; empty by default so a
        # misconfigured install fails loudly instead of messaging a stranger.
        "account": "",
        "recipient": "",            # where alerts go (phone or group:...)
        "send_timeout": 15.0,
        "retry": 2,
        "retry_backoff": 30.0,         # seconds; also caps outage-alert cooldown
    },
    "notify_on": ["warning", "critical"],
    "paths": {
        "state_file": "~/.local/state/hermes-sentinel/state.json",
        "log_file": "~/.local/state/hermes-sentinel/sentinel.log",
        "auth_log": "/var/log/auth.log",
    },
    "detectors": {
        "hermes_logs": True,
        "gateway_state": True,
        "integrity": True,
        "sessions": True,
        "system_auth": True,
    },
    "integrity": {
        # Only stable credential/config files: the gateway itself rewrites
        # channel_directory.json periodically, which would spam alerts.
        "files": [
            "~/.hermes/auth.json",
            "~/.hermes/.env",
            "~/.hermes/config.yaml",
        ],
    },
    "allowed_users": [],            # e.g. ["+1XXXXXXXXXX"] via env/config
    "quiet_hours": None,            # e.g. {"start": "23:00", "end": "07:00", "mute_info": true}
}


def _parse_env_value(raw: str) -> Any:
    """Parse an env string into YAML-ish scalars (lists, bools, numbers).

    Phone numbers keep their leading '+' (never coerced to int).
    Bare comma lists ("a,b") become lists when the key expects a list;
    handled by callers via _maybe_list.
    """
    raw = raw.strip()
    if raw.startswith("[") and raw.endswith("]"):
        inner = raw[1:-1].strip()
        return [_parse_env_value(x) for x in inner.split(",")] if inner else []
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "\"'":
        raw = raw[1:-1]
    if raw.lower() in ("true", "false"):
        return raw.lower() == "true"
    if not raw.startswith("+"):
        try:
            return int(raw)
        except ValueError:
            pass
        try:
            return float(raw)
        except ValueError:
            pass
    return raw


# Config keys whose values are lists in DEFAULTS; a comma-separated env
# string for these is split into a list.
_LIST_KEYS = {"allowed_users", "notify_on"}


def _maybe_list(dotted_key: str, value: Any, default: Any) -> Any:
    if dotted_key in _LIST_KEYS and isinstance(value, str) and "," in value:
        return [_parse_env_value(x) for x in value.split(",") if x.strip()]
    return value


def load_env_file() -> None:
    """Load KEY=VALUE pairs from a .env file into os.environ (no clobber)."""
    path = Path(os.environ.get(
        "HERMES_SENTINEL_ENV", str(PROJECT_ROOT / ".env"))).expanduser()
    try:
        lines = path.read_text().splitlines()
    except OSError:
        return
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip("'\"")
        if key and key not in os.environ:
            os.environ[key] = value


def apply_env_overrides(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Deep-copy cfg with ENV_OVERRIDES applied (real env wins)."""
    out = _deep_copy(cfg)

    def set_nested(d: Dict[str, Any], dotted: str, value: Any) -> None:
        parts = dotted.split(".")
        node = d
        for part in parts[:-1]:
            child = node.get(part)
            if not isinstance(child, dict):
                child = {}
                node[part] = child
            node = child
        node[parts[-1]] = value

    for dotted, env_name in ENV_OVERRIDES.items():
        raw = os.environ.get(env_name)
        if raw is not None and raw.strip() != "":
            value = _parse_env_value(raw)
            set_nested(out, dotted, _maybe_list(dotted, value, out.get(dotted)))
    return out


def _merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def _deep_copy(d: Dict[str, Any]) -> Dict[str, Any]:
    return {k: (_deep_copy(v) if isinstance(v, dict) else
               (list(v) if isinstance(v, list) else v))
            for k, v in d.items()}


def _load_yaml(path: Path) -> Dict[str, Any]:
    text = path.read_text()
    try:
        import yaml  # type: ignore

        data = yaml.safe_load(text)
        return data if isinstance(data, dict) else {}
    except ImportError:
        return _mini_yaml(text)


def _mini_yaml(text: str) -> Dict[str, Any]:
    """Tiny subset YAML parser: nested maps, scalars, inline lists, comments."""
    root: Dict[str, Any] = {}
    stack: List[tuple[int, Dict[str, Any]]] = [(-1, root)]

    def scalar(s: str) -> Any:
        s = s.strip()
        if s.startswith("[") and s.endswith("]"):
            inner = s[1:-1].strip()
            return [scalar(x) for x in inner.split(",")] if inner else []
        if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
            return s[1:-1]
        if s.lower() in ("true", "false"):
            return s.lower() == "true"
        try:
            return int(s)
        except ValueError:
            pass
        try:
            return float(s)
        except ValueError:
            pass
        return s

    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip() if not raw.lstrip().startswith("#") else ""
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        if ":" not in line:
            continue
        key, _, rest = line.strip().partition(":")
        while stack and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1]
        if rest.strip() == "":
            child: Dict[str, Any] = {}
            parent[key.strip()] = child
            stack.append((indent, child))
        else:
            parent[key.strip()] = scalar(rest)
    return root


@dataclass
class Config:
    raw: Dict[str, Any]
    origin: Optional[Path] = None

    @classmethod
    def load(cls, path: Optional[str] = None) -> "Config":
        load_env_file()
        candidates: List[Path] = []
        if path:
            candidates.append(Path(path).expanduser())
        else:
            env = os.environ.get("HERMES_SENTINEL_CONFIG")
            if env:
                candidates.append(Path(env).expanduser())
            candidates += [
                PROJECT_ROOT / "config" / "sentinel.local.yaml",
                PROJECT_ROOT / "config" / "sentinel.yaml",
                Path.home() / ".config" / "hermes-sentinel" / "sentinel.yaml",
                Path("/etc/hermes-sentinel/sentinel.yaml"),
            ]
        file_cfg = _deep_copy(DEFAULTS)
        origin: Optional[Path] = None
        for cand in candidates:
            if cand.is_file():
                file_cfg = _merge(DEFAULTS, _load_yaml(cand))
                origin = cand
                break
        return cls(apply_env_overrides(file_cfg), origin=origin)

    def get(self, dotted: str, default: Any = None) -> Any:
        node: Any = self.raw
        for part in dotted.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    def expand(self, value: str) -> Path:
        return Path(os.path.expanduser(str(value)))

    def validate(self) -> List[str]:
        """Return a list of human-readable configuration problems."""
        problems: List[str] = []
        if not self.signal_account:
            problems.append(
                "signal.account is not set (env SIGNAL_ACCOUNT or config)")
        if not self.signal_recipient:
            problems.append(
                "signal.recipient is not set (env SIGNAL_RECIPIENT or config)")
        return problems

    # convenience accessors -------------------------------------------------
    @property
    def hermes_home(self) -> Path:
        from_env = os.environ.get("HERMES_HOME", "")
        from_cfg = self.get("hermes_home", "")
        return Path(os.path.expanduser(str(from_cfg or from_env or Path.home() / ".hermes")))

    @property
    def signal_url(self) -> str:
        return str(self.get("signal.http_url", DEFAULTS["signal"]["http_url"]))

    @property
    def signal_account(self) -> str:
        return str(self.get("signal.account", ""))

    @property
    def signal_recipient(self) -> str:
        return str(self.get("signal.recipient", ""))

    @property
    def state_file(self) -> Path:
        return self.expand(self.get("paths.state_file", DEFAULTS["paths"]["state_file"]))

    @property
    def log_file(self) -> Path:
        return self.expand(self.get("paths.log_file", DEFAULTS["paths"]["log_file"]))

    @property
    def notify_on(self) -> List[str]:
        v = self.get("notify_on", DEFAULTS["notify_on"])
        return list(v) if isinstance(v, list) else ["warning", "critical"]

    def detector_enabled(self, name: str) -> bool:
        return bool(self.get(f"detectors.{name}", True))