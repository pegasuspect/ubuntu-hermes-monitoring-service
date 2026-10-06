"""Hermes log watchers: agent.log / errors.log patterns + signal outage.

All patterns are derived from real lines found in this system's logs:

  unauthorized drops:  "Dropping message from unauthorized user in active
                        session: user=+1..., platform=signal, session=..."
  signal outage:        "Signal: cannot reach signal-cli at http://..."
                        (recoverable -> warning, persistent -> critical)
  respawn storm:        "Gateway (re)started N times in Xs — backing off..."
                        (ERROR "Another gateway instance is already running"
                        is treated as part of the storm family)
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..events import Event, Severity
from ..tailer import FileTail
from ..util import parse_log_ts
from . import Detector

LINE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3})\s+"
    r"(?P<level>DEBUG|INFO|WARNING|ERROR|CRITICAL)\s+"
    r"(?P<logger>[\w.]+):\s+(?P<msg>.*)$"
)

PATTERNS: List[Tuple[str, re.Pattern, Severity, str]] = [
    (
        "unauthorized-message",
        re.compile(
            r"Dropping message from unauthorized user in active session:\s*"
            r"user=(?P<user>\S+)\s+\((?P<name>[^)]*)\),\s*"
            r"platform=(?P<platform>\w+),\s*session=(?P<session>\S+)"
        ),
        Severity.CRITICAL,
        "Unauthorized user messaged an active hermes session",
    ),
    (
        "unauthorized-resume",
        re.compile(
            r"Skipping auto-resume for (?P<session>\S+):\s*session owner is no"
            r" longer authorized"
        ),
        Severity.WARNING,
        "Session owner removed from allowlist tried to resume",
    ),
    (
        "respawn-storm",
        re.compile(
            r"Gateway \(re\)started (?P<n>\d+) times in (?P<win>\d+)s"
        ),
        Severity.WARNING,
        "Gateway restart storm detected",
    ),
    (
        "double-gateway",
        re.compile(r"Another gateway instance is already running \(PID (?P<pid>\d+)"),
        Severity.WARNING,
        "Second gateway instance attempted to start",
    ),
    (
        "signal-outage",
        re.compile(r"Signal: cannot reach signal-cli at (?P<url>\S+)"),
        Severity.WARNING,
        "Signal adapter lost connection to signal-cli",
    ),
]

IGNORED = re.compile(
    r"memory trim|Shutdown context|Shutdown phase|SIGTERM|no-receive-stdout"
)


class HermesLogDetector(Detector):
    """Tails agent.log + errors.log and matches security-relevant patterns."""

    def __init__(self, name: str, hermes_home: Path, allowed_users: List[str],
                 signal_outage_critical_after: int = 3, **kwargs) -> None:
        super().__init__(name, hermes_home, **kwargs)
        self.allowed_users = {u.strip() for u in allowed_users if str(u).strip()}
        self.signal_outage_critical_after = signal_outage_critical_after
        self._tails: Dict[Path, FileTail] = {}
        self._signal_outage_streak = 0

    def _tail(self, path: Path) -> Optional[FileTail]:
        if path not in self._tails:
            if not path.exists():
                return None
            self._tails[path] = FileTail(path)
        return self._tails[path]

    def poll(self) -> List[Event]:
        events: List[Event] = []
        for rel in ("logs/agent.log", "logs/errors.log", "logs/gateway.log"):
            path = self.hermes_home / rel
            tail = self._tail(path)
            if tail is None:
                continue
            events.extend(self._process(tail.poll(), path))
        return events

    def _process(self, lines, path: Path) -> List[Event]:
        events: List[Event] = []
        for line in lines:
            m = LINE_RE.match(line)
            if not m:
                continue
            msg = m.group("msg")
            level = m.group("level")
            if IGNORED.search(msg):
                # shutdown noise / housekeeping
                self._signal_outage_streak = 0
                continue
            ts = parse_log_ts(m.group("ts"))
            matched = False
            for kind, pat, sev, title in PATTERNS:
                pm = pat.search(msg)
                if not pm:
                    continue
                matched = True
                if kind == "signal-outage":
                    events.append(self._signal_outage_event(pm, ts))
                else:
                    detail = self._detail(kind, pm)
                    events.append(Event(
                        source=f"hermes.{path.name}",
                        kind=kind,
                        title=title,
                        severity=self._severity_for(kind, sev, pm),
                        detail=detail,
                        timestamp=ts or Event.now(),
                        context={"logger": m.group("logger"), "level": level,
                                 **{k: v for k, v in pm.groupdict().items()},
                                 "raw": line[:400]},
                    ))
                break
            if not matched:
                self._signal_outage_streak = 0
        return events

    # per-kind handling ------------------------------------------------------
    def _signal_outage_event(self, pm: re.Match, ts: Optional[float]) -> Event:
        self._signal_outage_streak += 1
        sev = (Severity.CRITICAL
               if self._signal_outage_streak >= self.signal_outage_critical_after
               else Severity.WARNING)
        return Event(
            source="hermes.signal",
            kind="signal-outage",
            title="Signal adapter cannot reach signal-cli",
            severity=sev,
            detail=(f"signal-cli at {pm.group('url')} unreachable "
                    f"(streak={self._signal_outage_streak})"),
            timestamp=ts or Event.now(),
        )

    def _severity_for(self, kind: str, base: Severity, pm: re.Match) -> Severity:
        if kind == "unauthorized-message":
            user = pm.group("user")
            # a previously-allowed user losing access is still noteworthy,
            # but a total stranger is critical by default anyway
            return Severity.CRITICAL
        return base

    def _detail(self, kind: str, pm: re.Match) -> str:
        g = pm.groupdict()
        if kind == "unauthorized-message":
            return (f"user {g.get('user','?')} ('{g.get('name','?')}') on "
                    f"{g.get('platform','?')} -> session {g.get('session','?')}")
        if kind == "unauthorized-resume":
            return f"session {g.get('session','?')}"
        if kind == "respawn-storm":
            return (f"{g.get('n','?')} restarts in {g.get('win','?')}s — "
                    f"possible crash loop or tampering")
        if kind == "double-gateway":
            return f"conflicting gateway already running with PID {g.get('pid','?')}"
        return ", ".join(f"{k}={v}" for k, v in g.items())