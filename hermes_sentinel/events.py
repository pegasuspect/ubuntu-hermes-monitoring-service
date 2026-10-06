"""Event and severity model shared across detectors."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional


class Severity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"

    @property
    def weight(self) -> int:
        return {"info": 0, "warning": 1, "critical": 2}[self.value]

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls(value.strip().lower())
        except ValueError:
            return cls.WARNING


@dataclass
class Event:
    """A single observation worth reporting (or deduplicating)."""

    source: str                     # detector name, e.g. "hermes.agent-log"
    kind: str                       # stable event type, e.g. "unauthorized-dm"
    title: str                      # short human label
    severity: Severity
    detail: str = ""                # one-line detail for the alert body
    fingerprint: str = ""           # dedup key (defaults to source+kind+detail)
    timestamp: float = field(default_factory=time.time)
    context: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.fingerprint:
            self.fingerprint = f"{self.source}:{self.kind}:{self.detail[:160]}"

    @classmethod
    def now(cls) -> float:
        return time.time()

    def as_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "kind": self.kind,
            "title": self.title,
            "severity": self.severity.value,
            "detail": self.detail,
            "fingerprint": self.fingerprint,
            "timestamp": self.timestamp,
            "context": self.context,
        }

    def render(self, host: str = "") -> str:
        """Markdown-ish body for a Signal message (Signal bold = **text**)."""
        sev = self.severity.value.upper()
        lines = [f"**[{sev}] {self.title}**", ""]
        if self.detail:
            lines.append(self.detail)
        lines.append("")
        when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.timestamp))
        where = f" on {host}" if host else ""
        lines.append(f"_{self.source} · {when}{where}_")
        return "\n".join(lines)


def event_from_dict(d: Dict[str, Any]) -> Event:
    return Event(
        source=d.get("source", "unknown"),
        kind=d.get("kind", "unknown"),
        title=d.get("title", "Event"),
        severity=Severity.parse(d.get("severity", "warning")),
        detail=d.get("detail", ""),
        fingerprint=d.get("fingerprint", ""),
        timestamp=float(d.get("timestamp", time.time())),
        context=d.get("context", {}) or {},
    )


def json_dumps(obj: Any) -> str:
    def _default(o: Any) -> Any:
        if isinstance(o, Event):
            return o.as_dict()
        if isinstance(o, Severity):
            return o.value
        raise TypeError(f"not serializable: {type(o)}")

    return json.dumps(obj, default=_default, indent=2)