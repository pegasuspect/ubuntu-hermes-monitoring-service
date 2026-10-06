"""Persistent state: event ledger for dedup, cooldown, escalation.

The state file is small JSON kept under ~/.local/state/hermes-sentinel/.
It survives restarts so a flapping detector doesn't re-alert after
service restarts.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from .events import Event, Severity, event_from_dict

MAX_FINGERPRINTS = 5000


class Ledger:
    """Tracks fingerprints: last-seen, count, cooldown, escalation."""

    def __init__(self, state_file: Path, cooldown: float = 900.0,
                 escalate_after: int = 3) -> None:
        self.state_file = state_file
        self.cooldown = cooldown
        self.escalate_after = escalate_after
        self._entries: Dict[str, Dict[str, Any]] = {}
        self._dirty = False
        self._load()

    # persistence -----------------------------------------------------------
    def _load(self) -> None:
        try:
            data = json.loads(self.state_file.read_text())
            entries = data.get("entries", {})
            if isinstance(entries, dict):
                self._entries = entries
        except (OSError, ValueError):
            self._entries = {}

    def save(self) -> None:
        if not self._dirty:
            return
        now = time.time()
        # prune entries not seen for 30 days or beyond cap (oldest first)
        for fp in list(self._entries):
            if now - self._entries[fp].get("last_seen", 0) > 30 * 86400:
                del self._entries[fp]
        if len(self._entries) > MAX_FINGERPRINTS:
            ordered = sorted(self._entries.items(),
                             key=lambda kv: kv[1].get("last_seen", 0))
            for fp, _ in ordered[:len(self._entries) - MAX_FINGERPRINTS]:
                del self._entries[fp]
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = tempfile.NamedTemporaryFile(
            "w", dir=str(self.state_file.parent), delete=False, suffix=".tmp")
        try:
            json.dump({"entries": self._entries, "saved_at": now}, tmp)
            tmp.flush()
            os.fsync(tmp.fileno())
            tmp.close()
            os.replace(tmp.name, self.state_file)
            self._dirty = False
        finally:
            if not tmp.closed:
                tmp.close()

    # core --------------------------------------------------------------------
    def filter_new(self, events: List[Event]) -> List[Event]:
        """Return events that should actually be reported.

        Applies: cooldown suppression, repeat-count escalation,
        severity floor from notify_on (checked by caller separately).
        Mutates ledger state (counts/last_seen) for every input event.
        """
        now = time.time()
        report: List[Event] = []
        for ev in events:
            entry = self._entries.get(ev.fingerprint)
            if entry is None:
                entry = {"count": 0, "first_seen": now, "last_alerted": 0.0,
                         "last_seen": 0.0, "max_severity": Severity.INFO.value}
                self._entries[ev.fingerprint] = entry
            entry["count"] = int(entry.get("count", 0)) + 1
            entry["last_seen"] = now
            entry["detail"] = ev.detail[:200]
            entry["source"] = ev.source
            entry["kind"] = ev.kind

            count = entry["count"]
            last_alerted = float(entry.get("last_alerted", 0.0))

            # escalation: same thing keeps happening -> bump severity
            if count >= self.escalate_after and ev.severity.weight < Severity.CRITICAL.weight:
                ev.severity = Severity.CRITICAL
                ev.title = f"{ev.title} (x{count})"

            if now - last_alerted >= self.cooldown:
                entry["last_alerted"] = now
                entry["max_severity"] = max(entry.get("max_severity", "info"),
                                            ev.severity.value)
                report.append(ev)
            self._dirty = True
        return report

    def reset(self, fingerprint: Optional[str] = None) -> None:
        if fingerprint:
            self._entries.pop(fingerprint, None)
        else:
            self._entries.clear()
        self._dirty = True

    def stats(self) -> Dict[str, Any]:
        return {
            "tracked_fingerprints": len(self._entries),
            "cooldown": self.cooldown,
            "escalate_after": self.escalate_after,
        }

    def recent(self, limit: int = 20) -> List[Dict[str, Any]]:
        items = sorted(self._entries.items(),
                       key=lambda kv: kv[1].get("last_seen", 0), reverse=True)
        out: List[Dict[str, Any]] = []
        for fp, entry in items[:limit]:
            row = {"fingerprint": fp}
            row.update(entry)
            out.append(row)
        return out


def load_events_journal(path: Path, limit: int = 100) -> List[Event]:
    """Read previously emitted events from the journal file (JSON lines)."""
    out: List[Event] = []
    try:
        with path.open() as fh:
            lines = fh.readlines()
        for line in reversed(lines[-limit * 2:]):
            line = line.strip()
            if not line:
                continue
            try:
                out.append(event_from_dict(json.loads(line)))
            except ValueError:
                continue
            if len(out) >= limit:
                break
    except OSError:
        pass
    return out