"""Base class for all detectors."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import List

from ..events import Event


class Detector(ABC):
    name: str = "detector"

    def __init__(self, name: str, hermes_home: Path, **kwargs) -> None:
        self.name = name
        self.hermes_home = hermes_home

    @abstractmethod
    def poll(self) -> List[Event]:
        """Return events observed since the last poll (possibly empty)."""

    def startup(self) -> None:
        pass