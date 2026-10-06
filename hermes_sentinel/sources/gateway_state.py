"""Gateway state watcher: heartbeat freshness, PID health, restart storms.

Sources:
  ~/.hermes/state/gateway.heartbeat     -> PID, updated_at, memory
  ~/.hermes/gateway-starts.log          -> epoch timestamps of every start
  ~/.hermes/state/gateway.lifecycle.json
"""

from __future__ import annotations

import time
from typing import List

from ..events import Event, Severity
from ..util import pid_alive, read_json
from . import Detector


class GatewayStateDetector(Detector):
    def __init__(self, name: str, hermes_home: Path,
                 expected_interval: float = 60.0,
                 stale_after: float = 180.0,
                 grace: float = 60.0,
                 restart_window: float = 300.0,
                 restart_threshold: int = 3, **kwargs) -> None:
        super().__init__(name, hermes_home, **kwargs)
        self.expected_interval = expected_interval
        self.stale_after = stale_after
        self.grace = grace
        self.restart_window = restart_window
        self.restart_threshold = restart_threshold
        self._started_at = time.time()
        self._last_starts_count = None

    def poll(self) -> List[Event]:
        events: List[Event] = []
        events.extend(self._check_heartbeat())
        events.extend(self._check_restarts())
        return events

    # heartbeat --------------------------------------------------------------
    def _check_heartbeat(self) -> List[Event]:
        hb = read_json(self.hermes_home / "state" / "gateway.heartbeat")
        if hb is None:
            # No heartbeat file yet; only report if gateway claims to run
            gw_state = read_json(self.hermes_home / "gateway_state.json") or {}
            if gw_state.get("gateway_state") == "running":
                return [Event(
                    source="hermes.gateway-state",
                    kind="heartbeat-missing",
                    title="Gateway claims running but heartbeat file missing",
                    severity=Severity.WARNING,
                    detail="state/gateway.heartbeat not found while gateway_state=running",
                )]
            return []
        if not isinstance(hb, dict):
            return []

        pid = hb.get("pid")
        updated_at = hb.get("updated_at")
        now = time.time()

        try:
            updated_epoch = _parse_iso(updated_at)
        except (TypeError, ValueError):
            return []
        if updated_epoch is None:
            return []

        if pid and not pid_alive(int(pid)):
            return [Event(
                source="hermes.gateway-state",
                kind="gateway-pid-dead",
                title="Gateway heartbeat PID is not running",
                severity=Severity.CRITICAL,
                detail=f"heartbeat pid={pid} has no live process "
                       f"(updated_at={updated_at})",
            )]

        age = now - updated_epoch
        if age > self.stale_after and (now - self._started_at) > self.grace:
            return [Event(
                source="hermes.gateway-state",
                kind="heartbeat-stale",
                title="Gateway heartbeat is stale",
                severity=Severity.WARNING,
                detail=f"last heartbeat {int(age)}s ago (pid={pid}) — "
                       f"gateway may be hung or killed",
            )]
        return []

    # restart storm ------------------------------------------------------------
    def _check_restarts(self) -> List[Event]:
        path = self.hermes_home / "gateway-starts.log"
        try:
            lines = [l.strip() for l in path.read_text().splitlines() if l.strip()]
        except OSError:
            return []
        if not lines:
            return []

        # New-start detection: emit event only for starts we haven't seen.
        count = len(lines)
        if self._last_starts_count is None:
            self._last_starts_count = count
            return []
        if count < self._last_starts_count:
            self._last_starts_count = count  # log rotated/cleared
            return []
        new = count - self._last_starts_count
        self._last_starts_count = count

        now = time.time()
        recent = [float(x) for x in lines if _safe_float(x) and now - _safe_float(x) <= self.restart_window]
        if new:
            ev = Event(
                source="hermes.gateway-state",
                kind="gateway-restarted",
                title="Hermes gateway (re)started",
                severity=Severity.INFO,
                detail=f"{new} new start(s); {len(recent)} within "
                       f"{int(self.restart_window)}s window",
            )
            if len(recent) >= self.restart_threshold:
                ev.severity = Severity.WARNING
                ev.kind = "restart-storm"
                ev.title = "Gateway restart storm"
            return [ev]
        return []


def _parse_iso(value) -> float | None:
    if value is None:
        return None
    from datetime import datetime
    try:
        return datetime.fromisoformat(str(value)).timestamp()
    except ValueError:
        return None


def _safe_float(x: str) -> float:
    try:
        return float(x)
    except ValueError:
        return -1e18