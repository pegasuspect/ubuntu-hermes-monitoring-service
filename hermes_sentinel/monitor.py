"""Monitor: wires detectors -> ledger -> Signal notifier, as a daemon loop.

Also self-monitors: if signal-cli itself is unreachable, the outage is
logged and retried; queued alerts survive until delivery or expiry.
"""

from __future__ import annotations

import json
import logging
import os
import queue
import signal
import threading
import time
from pathlib import Path
from typing import List, Optional

from .config import Config
from .events import Event, Severity
from .ledger import Ledger
from .notifier import SignalNotifier
from .sources.gateway_state import GatewayStateDetector
from .sources.hermes_logs import HermesLogDetector
from .sources.integrity import IntegrityDetector
from .sources.sessions import SessionsDetector
from .sources.system_auth import SystemAuthDetector
from .util import hostname

LOG = logging.getLogger("hermes-sentinel")

QUEUE_MAX = 500
QUEUE_TTL = 6 * 3600  # undelivered alerts expire after 6h


class Monitor:
    def __init__(self, config: Config, dry_run: bool = False) -> None:
        self.config = config
        self.dry_run = dry_run
        self.host = hostname()
        self.stop_event = threading.Event()
        self._threads: List[threading.Thread] = []
        self.event_queue: "queue.Queue[Event]" = queue.Queue(maxsize=QUEUE_MAX)
        self._queued_alerts: List[Event] = []  # events awaiting Signal delivery
        self._queue_lock = threading.Lock()

        self.ledger = Ledger(
            config.state_file,
            cooldown=float(config.get("cooldown", 900.0)),
            escalate_after=int(config.get("escalate_after", 3)),
        )
        self.notifier = SignalNotifier(
            http_url=config.signal_url,
            account=config.signal_account,
            recipient="" if dry_run else config.signal_recipient,
            timeout=float(config.get("signal.send_timeout", 15.0)),
            retry=int(config.get("signal.retry", 2)),
            retry_backoff=float(config.get("signal.retry_backoff", 30.0)),
        )
        self.journal_path = config.log_file
        self._journal_fh = None

    # construction of detectors ------------------------------------------------
    def build_detectors(self) -> List:
        dets = []
        hh = self.config.hermes_home
        allowed = self.config.get("allowed_users", [])
        if self.config.detector_enabled("hermes_logs"):
            dets.append(HermesLogDetector(
                "hermes-logs", hh,
                allowed_users=allowed,
            ))
        if self.config.detector_enabled("gateway_state"):
            hb = self.config.get("heartbeat", {})
            rs = self.config.get("restart_storm", {})
            dets.append(GatewayStateDetector(
                "gateway-state", hh,
                expected_interval=float(hb.get("expected_interval", 60.0)),
                stale_after=float(hb.get("stale_after", 180.0)),
                grace=float(hb.get("grace", 60.0)),
                restart_window=float(rs.get("window", 300.0)),
                restart_threshold=int(rs.get("threshold", 3)),
            ))
        if self.config.detector_enabled("integrity"):
            files = self.config.get("integrity.files", None) or None
            dets.append(IntegrityDetector("integrity", hh, files=files))
        if self.config.detector_enabled("sessions"):
            dets.append(SessionsDetector("sessions", hh, allowed_users=allowed))
        if self.config.detector_enabled("system_auth"):
            dets.append(SystemAuthDetector(
                "system-auth", hh,
                auth_log=str(self.config.get(
                    "paths.auth_log", "/var/log/auth.log")),
                brute_force_window=float(self.config.get(
                    "brute_force.window", 300.0)),
                brute_force_threshold=int(self.config.get(
                    "brute_force.threshold", 10)),
            ))
        return dets

    # logging --------------------------------------------------------------
    def setup_logging(self, verbose: bool = False) -> None:
        self.journal_path.parent.mkdir(parents=True, exist_ok=True)
        handlers: List[logging.Handler] = []
        fh = logging.FileHandler(self.journal_path)
        fh.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)s %(name)s: %(message)s"))
        handlers.append(fh)
        sh = logging.StreamHandler()
        sh.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
        handlers.append(sh)
        logging.basicConfig(
            level=logging.DEBUG if verbose else logging.INFO,
            handlers=handlers, force=True)
        self._journal_fh = fh

    def _log_event(self, ev: Event) -> None:
        self.journal_path.parent.mkdir(parents=True, exist_ok=True)
        LOG.log(
            logging.CRITICAL if ev.severity == Severity.CRITICAL else logging.INFO,
            "EVENT %s %s %s %s",
            ev.severity.value.upper(), ev.kind, ev.title, ev.detail,
        )

    # pipeline ----------------------------------------------------------------
    def process_events(self, events: List[Event]) -> None:
        if not events:
            return
        for ev in events:
            LOG.info("detected [%s] %s: %s", ev.severity.value, ev.kind, ev.detail or ev.title)
        fresh = self.ledger.filter_new(events)
        for ev in fresh:
            self._log_event(ev)
        to_alert = [e for e in fresh if self._should_notify(e)]
        if to_alert:
            self.enqueue_alerts(to_alert)
        self.ledger.save()

    def _should_notify(self, ev: Event) -> bool:
        # notify_on lists every severity we alert on; the floor is the lowest
        floor = min(Severity.parse(s).weight for s in self.config.notify_on)
        if self._quiet_hours_mute(ev):
            return False
        return ev.severity.weight >= floor

    def _quiet_hours_mute(self, ev: Event) -> bool:
        qh = self.config.get("quiet_hours")
        if not qh:
            return False
        if not isinstance(qh, dict) or not qh.get("start") or not qh.get("end"):
            return False
        if not qh.get("mute_info", True):
            # mute everything during quiet hours regardless
            pass
        start = _hhmm_to_min(str(qh["start"]))
        end = _hhmm_to_min(str(qh["end"]))
        now = time.localtime()
        cur = now.tm_hour * 60 + now.tm_min
        if _in_window(cur, start, end):
            return ev.severity == Severity.INFO if qh.get("mute_info", True) else False
        return False

    # alert queue ---------------------------------------------------------
    def enqueue_alerts(self, events: List[Event]) -> None:
        with self._queue_lock:
            self._queued_alerts.extend(events)

    def _drain_alerts(self) -> int:
        with self._queue_lock:
            batch, self._queued_alerts = self._queued_alerts, []
        if not batch:
            return 0
        now = time.time()
        batch = [e for e in batch if now - e.timestamp <= QUEUE_TTL]
        if self.dry_run:
            for ev in batch:
                print(f"[dry-run] would send to {self.config.signal_recipient}:\n"
                      f"{ev.render(self.host)}\n")
            return len(batch)
        sent, skipped, err = self.notifier.notify(batch, host=self.host,
                                                  notify_on=self.config.notify_on)
        if err:
            LOG.warning("signal delivery failed: %s — requeueing %d alert(s)",
                        err, skipped)
            with self._queue_lock:
                self._queued_alerts = batch + self._queued_alerts
        else:
            LOG.info("signal: sent %d alert(s), skipped %d", sent, skipped)
        return sent

    # detector threads ---------------------------------------------------------
    def _run_detector(self, det, interval: float) -> None:
        LOG.debug("detector %s started (interval=%.1fs)", det.name, interval)
        while not self.stop_event.is_set():
            try:
                events = det.poll()
                for ev in events[: int(self.config.get("max_events_per_sweep", 50))]:
                    try:
                        self.event_queue.put(ev, timeout=2.0)
                    except queue.Full:
                        LOG.warning("event queue full; dropping event from %s", det.name)
            except Exception:
                LOG.exception("detector %s crashed; restarting", det.name)
                time.sleep(10)
            self.stop_event.wait(interval)

    def _run_dispatcher(self, drain_interval: float = 2.0) -> None:
        while not self.stop_event.is_set():
            try:
                self._drain_alerts()
            except Exception:
                LOG.exception("dispatcher failed")
            self.stop_event.wait(drain_interval)

    def _run_consumer(self) -> None:
        while not self.stop_event.is_set():
            try:
                ev = self.event_queue.get(timeout=1.0)
            except queue.Empty:
                continue
            batch = [ev]
            while len(batch) < 20:
                try:
                    batch.append(self.event_queue.get_nowait())
                except queue.Empty:
                    break
            try:
                self.process_events(batch)
            except Exception:
                LOG.exception("failed processing event batch")

    # lifecycle ------------------------------------------------------------
    def start(self) -> None:
        LOG.info("hermes-sentinel starting on %s (config=%s, dry_run=%s)",
                 self.host, self.config.origin, self.dry_run)
        detectors = self.build_detectors()
        for det in detectors:
            det.startup()
        intervals = {
            "hermes-logs": float(self.config.get("tail_interval", 5.0)),
            "gateway-state": float(self.config.get("poll_interval", 10.0)),
            "integrity": float(self.config.get("poll_interval", 10.0)),
            "sessions": float(self.config.get("poll_interval", 10.0)),
            "system-auth": float(self.config.get("tail_interval", 5.0)),
        }
        for det in detectors:
            t = threading.Thread(
                target=self._run_detector, args=(det, intervals.get(det.name, 10.0)),
                name=f"det-{det.name}", daemon=True)
            t.start()
            self._threads.append(t)
        for name, target in (("consumer", self._run_consumer),
                             ("dispatcher", self._run_dispatcher)):
            t = threading.Thread(target=target, name=name, daemon=True)
            t.start()
            self._threads.append(t)

        def _sig(_sig, _frm):
            self.stop()

        if threading.current_thread() is threading.main_thread():
            signal.signal(signal.SIGTERM, _sig)
            signal.signal(signal.SIGINT, _sig)
        LOG.info("hermes-sentinel running (%d detectors)", len(detectors))

        while not self.stop_event.is_set():
            time.sleep(1.0)

        self.shutdown()

    def stop(self) -> None:
        self.stop_event.set()

    def shutdown(self) -> None:
        LOG.info("hermes-sentinel stopping")
        try:
            self._drain_alerts()
        except Exception:
            LOG.exception("final drain failed")
        self.ledger.save()
        if self._journal_fh:
            self._journal_fh.flush()
        LOG.info("hermes-sentinel stopped")


def _hhmm_to_min(s: str) -> int:
    try:
        h, m = s.split(":")
        return int(h) * 60 + int(m)
    except (ValueError, AttributeError):
        return 0


def _in_window(cur: int, start: int, end: int) -> bool:
    if start <= end:
        return start <= cur < end
    return cur >= start or cur < end  # wraps midnight