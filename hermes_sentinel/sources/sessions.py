"""Sessions detector: spots new or unknown messaging partners.

Reads ~/.hermes/sessions/sessions.json (legacy mirror of the routing index)
and flags:
  - sessions created by senders not in SIGNAL_ALLOWED_USERS/allowed_users
  - brand-new DM sessions appearing out of band (info-level FYI)

Note: the gateway itself only routes allowlisted senders, so a session
appearing from an unknown sender means either the allowlist changed or
pairing/policy allowed someone new — both worth knowing about.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Set

from ..events import Event, Severity
from ..util import read_json
from . import Detector


class SessionsDetector(Detector):
    def __init__(self, name: str, hermes_home: Path,
                 allowed_users: Optional[List[str]] = None, **kwargs) -> None:
        super().__init__(name, hermes_home, **kwargs)
        self.allowed: Set[str] = {str(u).strip() for u in (allowed_users or [])}
        self._known: Set[str] = set()

    def poll(self) -> List[Event]:
        path = self.hermes_home / "sessions" / "sessions.json"
        data = read_json(path)
        if not isinstance(data, dict):
            data = {}
        # skip the _README key
        entries = {k: v for k, v in data.items() if not k.startswith("_")}

        if not self._known and entries:
            # first poll: adopt existing sessions as known, no events
            self._known = set(entries.keys())
            return []

        events: List[Event] = []
        for key, val in entries.items():
            if key in self._known:
                continue
            self._known.add(key)
            if not isinstance(val, dict):
                continue
            origin = val.get("origin") or {}
            user_id = str(origin.get("user_id", ""))
            chat_type = val.get("chat_type", "?")
            platform = val.get("platform", "?")
            display = val.get("display_name", origin.get("user_name", "?"))

            if platform == "signal" and chat_type == "dm" and user_id and \
                    user_id not in self.allowed and "*" not in self.allowed:
                events.append(Event(
                    source="hermes.sessions",
                    kind="unknown-dm-session",
                    title="New Signal DM session from unknown sender",
                    severity=Severity.WARNING,
                    detail=f"{user_id} ('{display}') created session {val.get('session_id','?')}",
                    fingerprint=f"hermes.sessions:unknown-dm:{user_id}",
                ))
            else:
                events.append(Event(
                    source="hermes.sessions",
                    kind="new-session",
                    title=f"New {platform} {chat_type} session",
                    severity=Severity.INFO,
                    detail=f"'{display}' ({user_id or key[:60]})",
                ))
        # sessions that vanished are not security-relevant
        return events