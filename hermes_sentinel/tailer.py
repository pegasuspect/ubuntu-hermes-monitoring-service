"""Rotation-safe incremental file tailing.

Follows the classic inode+size strategy:
- regular growth  -> remember offset, read the new bytes
- truncation      -> reset to 0 (log was emptied)
- rotation        -> inode changed; read the new file from the start
Missing files are tolerated (poll again next sweep).

poll() eagerly returns the list of new complete lines; partial trailing
lines are held back (offset rewound) and picked up on the next poll.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


@dataclass
class TailState:
    inode: Optional[int] = None
    offset: int = 0


class FileTail:
    def __init__(self, path: Path, max_chunk_bytes: int = 1_000_000) -> None:
        self.path = path
        self.max_chunk = max_chunk_bytes
        self.state = TailState()

    def poll(self) -> List[str]:
        """Return newly appended complete lines since the last poll."""
        try:
            st = os.stat(self.path)
        except OSError:
            return []

        if not os.path.isfile(self.path):
            return []

        inode = st.st_ino
        size = st.st_size

        if self.state.inode != inode:
            # First sight, or rotation.
            first_sight = self.state.inode is None
            self.state = TailState(inode=inode, offset=size if first_sight else 0)
            if first_sight:
                return []  # skip backlog on startup; only watch new lines
        elif size < self.state.offset:
            # Truncated in place (same inode, smaller file)
            self.state.offset = 0

        if size <= self.state.offset:
            return []

        read_from = self.state.offset
        length = min(size - read_from, self.max_chunk)
        try:
            with self.path.open("rb") as fh:
                fh.seek(read_from)
                chunk = fh.read(length)
        except OSError:
            return []

        self.state.offset = read_from + len(chunk)
        data = chunk.decode("utf-8", errors="replace")

        lines: List[str] = []
        consumed = 0
        for line in data.splitlines(keepends=True):
            if line.endswith("\n"):
                lines.append(line.rstrip("\r\n"))
                consumed += len(line.encode("utf-8", errors="replace"))
            else:
                break  # partial trailing line: hold back for next poll
        if consumed < len(chunk):
            self.state.offset = read_from + consumed
        return lines