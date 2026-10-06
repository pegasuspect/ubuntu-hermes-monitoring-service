#!/usr/bin/env python3
"""hermes-sentinel: system-level security monitor for the Hermes agent.

Watches Hermes logs/state plus system auth logs, and pushes Signal alerts
when unusual or unauthorized activity is detected. Runs as a systemd user
service (with lingering enabled) so it starts at boot without login.

Std-library only at runtime; PyYAML is used only to load the config file
(falls back to a bundled minimal parser if unavailable).
"""

__version__ = "1.0.0"

from hermes_sentinel.events import Event, Severity
from hermes_sentinel.config import Config

__all__ = ["Event", "Severity", "Config", "__version__"]