"""Small shared helpers for detectors."""

from __future__ import annotations

import os
import socket
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Tuple


def hostname() -> str:
    return socket.gethostname() or "localhost"


def parse_log_ts(stamp: str) -> Optional[float]:
    """Parse 'YYYY-MM-DD HH:MM:SS,mmm' (hermes logs) -> epoch seconds."""
    try:
        return datetime.strptime(stamp.strip(), "%Y-%m-%d %H:%M:%S,%f").timestamp()
    except ValueError:
        try:
            return datetime.strptime(stamp.strip(), "%Y-%m-%d %H:%M:%S").timestamp()
        except ValueError:
            return None


def parse_syslog_ts(stamp: str, year: Optional[int] = None,
                    now: Optional[datetime] = None) -> Optional[float]:
    """Parse 'Mon DD HH:MM:SS' (syslog/auth.log) -> epoch, guessing the year."""
    try:
        now = now or datetime.now()
        year = year or now.year
        # auth.log zero-pads the day ("Oct  6"); handle 1-2 spaces
        parts = stamp.split()
        if len(parts) != 3:
            return None
        month = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
                 "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"].index(parts[0]) + 1
        day = int(parts[1])
        hh, mm, ss = (int(x) for x in parts[2].split(":"))
        dt = datetime(year, month, day, hh, mm, ss)
        # syslog has no year: if the guess lands in the future, it's last year
        if now - dt < - timedelta(days=1):
            dt = dt.replace(year=year - 1)
        return dt.timestamp()
    except (ValueError, IndexError):
        return None


def file_signature(path: Path) -> Optional[Tuple[int, int, int]]:
    """(mtime_ns, size, inode) tuple for integrity checks."""
    try:
        st = os.stat(path)
        return (st.st_mtime_ns, st.st_size, st.st_ino)
    except OSError:
        return None


def read_json(path: Path) -> Optional[object]:
    try:
        import json
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


def pid_alive(pid: Optional[int]) -> bool:
    if not pid:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except (TypeError, ValueError):
        return False


def monotonic_now() -> float:
    return time.monotonic()