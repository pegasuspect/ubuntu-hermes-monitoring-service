"""Integrity detector: watches security-critical hermes files for changes.

On first sight, baselines are recorded (no event). Any later change to
mtime/size/inode raises a CRITICAL event — e.g. someone editing auth.json,
.env, config.yaml, or the Signal channel directory.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..events import Event, Severity
from ..util import file_signature
from . import Detector


class IntegrityDetector(Detector):
    def __init__(self, name: str, hermes_home: Path,
                 files: Optional[List[str]] = None, **kwargs) -> None:
        super().__init__(name, hermes_home, **kwargs)
        self.targets: List[Path] = []
        raw = files or [
            "~/.hermes/auth.json",
            "~/.hermes/.env",
            "~/.hermes/config.yaml",
            "~/.hermes/channel_directory.json",
        ]
        for f in raw:
            p = Path(str(f)).expanduser()
            self.targets.append(p)
        self._baseline: Dict[Path, Optional[Tuple[int, int, int]]] = {}

    def poll(self) -> List[Event]:
        events: List[Event] = []
        for p in self.targets:
            sig = file_signature(p)
            prev = self._baseline.get(p, _MISSING)
            if sig is None:
                if prev not in (_MISSING, None):
                    events.append(Event(
                        source="hermes.integrity",
                        kind="file-deleted",
                        title="Watched hermes file disappeared",
                        severity=Severity.CRITICAL,
                        detail=str(p),
                    ))
                self._baseline[p] = None
                continue
            if prev is _MISSING or prev is None:
                self._baseline[p] = sig   # baseline on first sight
                continue
            if sig != prev:
                events.append(Event(
                    source="hermes.integrity",
                    kind="file-modified",
                    title="Watched hermes file was modified",
                    severity=Severity.CRITICAL,
                    detail=(f"{p} changed (size {prev[1]} -> {sig[1]}, "
                            f"inode {prev[2]} -> {sig[2]})"),
                ))
            self._baseline[p] = sig
        return events


_MISSING = object()