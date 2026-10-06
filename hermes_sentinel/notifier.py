"""Signal notifier: sends alerts through the local signal-cli JSON-RPC daemon.

Uses the same endpoint and payload format as the Hermes gateway itself
(http://127.0.0.1:8099/api/v1/rpc, method "send"), so alerts come from the
same linked Signal number. No extra registration or secrets needed.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from .events import Event, Severity


class SignalSendError(Exception):
    pass


class SignalNotifier:
    def __init__(self, http_url: str, account: str, recipient: str,
                 timeout: float = 15.0, retry: int = 2,
                 retry_backoff: float = 30.0) -> None:
        self.http_url = http_url.rstrip("/")
        self.account = account
        self.recipient = recipient
        self.timeout = timeout
        self.retry = retry
        self.retry_backoff = retry_backoff

    # low-level -------------------------------------------------------------
    def _rpc(self, method: str, params: Dict[str, Any]) -> Any:
        payload = json.dumps({
            "jsonrpc": "2.0", "method": method, "params": params, "id": int(time.time() * 1000)
        }).encode()
        req = urllib.request.Request(
            f"{self.http_url}/api/v1/rpc", data=payload,
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        if "error" in data:
            raise SignalSendError(str(data["error"]))
        return data.get("result")

    def check(self) -> bool:
        try:
            req = urllib.request.Request(f"{self.http_url}/api/v1/check")
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status == 200
        except (OSError, urllib.error.URLError):
            return False

    # send ------------------------------------------------------------------
    def send_message(self, text: str) -> Tuple[bool, Optional[str]]:
        """Send a text message to self.recipient. Returns (ok, error)."""
        if not self.recipient:
            return False, "no recipient configured"
        params: Dict[str, Any] = {"account": self.account, "message": text}
        if self.recipient.startswith("group:"):
            params["groupId"] = self.recipient[len("group:"):]
        else:
            params["recipient"] = [self.recipient]

        attempts = self.retry + 1
        last_err: Optional[str] = None
        for i in range(attempts):
            try:
                result = self._rpc("send", params)
                ok, err = self._validate(result)
                if ok:
                    return True, None
                last_err = err
            except (SignalSendError, OSError, urllib.error.URLError,
                    json.JSONDecodeError) as e:
                last_err = str(e)
            if i < attempts - 1:
                time.sleep(min(self.retry_backoff, 5.0))
        return False, last_err

    @staticmethod
    def _validate(result: Any) -> Tuple[bool, Optional[str]]:
        """Mirror of hermes gateway's send-result validation."""
        if not result or not isinstance(result, dict):
            return True, None
        results = result.get("results")
        if isinstance(results, list):
            for r in results:
                if not isinstance(r, dict):
                    continue
                rtype = r.get("type")
                if rtype and rtype != "SUCCESS":
                    return False, str(rtype)
                if "success" in r and not r.get("success"):
                    fail = r.get("failure")
                    return False, str(fail) if fail else "Recipient delivery failed"
        return True, None

    # alerts ------------------------------------------------------------------
    def notify(self, events: List[Event], host: str = "",
               notify_on: Optional[List[str]] = None) -> Tuple[int, int, Optional[str]]:
        """Send one Signal message per event (filtered by severity).

        Returns (sent, skipped, last_error). `skipped` counts events that
        were below the severity floor OR whose delivery failed.
        """
        notify_on = notify_on or ["warning", "critical"]
        floor = min(Severity.parse(s).weight for s in notify_on) if notify_on else 1
        sent = skipped = 0
        last_err: Optional[str] = None
        for ev in events:
            if ev.severity.weight < floor:
                skipped += 1
                continue
            ok, err = self.send_message(ev.render(host))
            if ok:
                sent += 1
            else:
                skipped += 1
                last_err = err
        return sent, skipped, last_err