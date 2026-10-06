"""System auth detector: watches /var/log/auth.log for brute force and
successful root SSH logins, sudo misuse, and new user creation.

Reads are possible because the service user is in the `adm` group.
Falls back to journalctl _COMM=sshd/sudo/su when the file is unreadable.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import List, Optional, Pattern

from ..events import Event, Severity
from ..tailer import FileTail
from ..util import parse_syslog_ts
from . import Detector

FAILED_SSH = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)"
)
ACCEPTED_SSH = re.compile(
    r"Accepted (?:publickey|password) for (?P<user>\S+) from (?P<ip>[\d.]+) port \d+"
)
BROKEN_PIPE = re.compile(r"Connection (?:closed|reset) by (?P<ip>[\d.]+)")
SUDO_EVENT = re.compile(r"(?P<user>\S+) :(?: TTY=\S+ .*?)? ; USER=(?P<target>\S+) ; COMMAND=(?P<cmd>.*)")
NEW_USER = re.compile(r"new user: name=(?P<name>\S+)")
INVALID = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)")


class SystemAuthDetector(Detector):
    """Tail auth.log (or journal fallback) for SSH/sudo/user events."""

    def __init__(self, name: str, hermes_home: Path,
                 auth_log: str = "/var/log/auth.log",
                 brute_force_window: float = 300.0,
                 brute_force_threshold: int = 10, **kwargs) -> None:
        super().__init__(name, hermes_home, **kwargs)
        self.auth_log = Path(auth_log)
        self.window = brute_force_window
        self.threshold = brute_force_threshold
        self._tail: Optional[FileTail] = None
        self._failures: List[tuple] = []  # (epoch, ip)

    def poll(self) -> List[Event]:
        lines = self._new_lines()
        events: List[Event] = []
        now_ts = None
        for line in lines:
            parts = line.split(maxsplit=4)
            if len(parts) < 5:
                continue
            ts = parse_syslog_ts(" ".join(parts[:3]))
            msg = parts[4]
            events.extend(self._match_one(line, msg, ts))
        # brute-force aggregate
        events.extend(self._check_bruteforce())
        return events

    def _new_lines(self) -> List[str]:
        if self.auth_log.is_file() and self._readable():
            if self._tail is None:
                self._tail = FileTail(self.auth_log)
            return list(self._tail.poll())
        return self._journal_fallback()

    def _readable(self) -> bool:
        try:
            with self.auth_log.open("rb") as fh:
                fh.read(1)
            return True
        except OSError:
            return False

    def _journal_fallback(self) -> List[str]:
        """Pull recent sshd/sudo/su lines from the journal (best effort)."""
        if not getattr(self, "_journal_warned", False):
            pass
        try:
            out = subprocess.run(
                ["journalctl", "-q", "--since", "-2m", "-t", "sshd", "-t", "sudo",
                 "-t", "su", "-t", "useradd", "--no-pager", "-o", "short"],
                capture_output=True, text=True, timeout=10,
            )
            lines = out.stdout.splitlines()
        except (OSError, subprocess.SubprocessError):
            return []
        # journal -o short: 'Mon DD HH:MM:SS host tag[pid]: msg'
        result: List[str] = []
        seen = getattr(self, "_journal_seen", None)
        new_seen = set()
        for line in lines:
            new_seen.add(line)
            if seen is None or line not in seen:
                result.append(line)
        self._journal_seen = new_seen
        return result

    def _match_one(self, line: str, msg: str, ts: Optional[float]) -> List[Event]:
        events: List[Event] = []
        m = ACCEPTED_SSH.search(msg)
        if m:
            events.append(Event(
                source="system.auth",
                kind="ssh-login",
                title=f"SSH login: {m['user']}",
                severity=Severity.INFO,
                detail=f"Accepted for {m['user']} from {m['ip']}",
                timestamp=ts or Event.now(),
            ))
            return events
        m = INVALID.search(msg)
        if m:
            self._failures.append((ts or Event.now(), m["ip"]))
            return events
        m = FAILED_SSH.search(msg)
        if m:
            self._failures.append((ts or Event.now(), m["ip"]))
            return events
        m = NEW_USER.search(msg)
        if m:
            events.append(Event(
                source="system.auth",
                kind="user-created",
                title="New system user created",
                severity=Severity.CRITICAL,
                detail=f"name={m['name']} — verify this was you",
                timestamp=ts or Event.now(),
            ))
        m = SUDO_EVENT.search(msg)
        if m and m["target"] == "root" and self._interesting_sudo(m["cmd"]):
            events.append(Event(
                source="system.auth",
                kind="sudo-root",
                title=f"Sudo to root by {m['user']}",
                severity=Severity.INFO,
                detail=f"USER=root COMMAND={m['cmd'][:120]}",
                timestamp=ts or Event.now(),
            ))
        return events

    @staticmethod
    def _interesting_sudo(cmd: str) -> bool:
        interesting = ("useradd", "passwd", "chpasswd", "systemctl", "nano",
                       "vim", "rm ", "curl", "wget", "chmod ", "chown ",
                       "visudo", "crontab")
        return any(t in cmd for t in interesting)

    def _check_bruteforce(self) -> List[Event]:
        import time as _t
        now = _t.time()
        self._failures = [f for f in self._failures if now - f[0] <= self.window]
        if len(self._failures) < self.threshold:
            return []
        ips = {}
        for _, ip in self._failures:
            ips[ip] = ips.get(ip, 0) + 1
        top_ip, top_n = max(ips.items(), key=lambda kv: kv[1])
        ev = Event(
            source="system.auth",
            kind="ssh-bruteforce",
            title="SSH brute force in progress",
            severity=Severity.WARNING,
            detail=(f"{len(self._failures)} failed logins in {int(self.window)}s "
                    f"(top: {top_ip} x{top_n})"),
            fingerprint="system.auth:ssh-bruteforce",
        )
        # consume the window to avoid immediate re-alert (ledger cooldown
        # also handles this, but reset makes counting restart cleanly)
        self._failures = []
        return [ev]