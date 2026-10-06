import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from hermes_sentinel.tailer import FileTail  # noqa: E402


def test_tail_growth_and_rotation():
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "app.log"
        t = FileTail(p)
        # file appears later
        assert list(t.poll()) == []
        p.write_text("line1\nline2\n")
        got = list(t.poll())
        assert got == []  # first sight: skip backlog
        p.open("a").write("line3\n")
        got = list(t.poll())
        assert got == ["line3"]
        # append two more
        with p.open("a") as fh:
            fh.write("line4\nline5\n")
        got = list(t.poll())
        assert got == ["line4", "line5"]
        # truncation
        p.write_text("fresh1\n")
        got = list(t.poll())
        assert got == ["fresh1"]
        # rotation: new inode with same name
        rotated = Path(td) / "app.log.1"
        p.rename(rotated)
        (Path(td) / "app.log").write_text("newfile1\n")
        got = list(t.poll())
        assert "newfile1" in got


def test_partial_line_held_back():
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "app.log"
        p.write_text("full\n")
        t = FileTail(p)
        t.poll()
        with p.open("a") as fh:
            fh.write("part")  # no newline yet
        assert list(t.poll()) == []
        with p.open("a") as fh:
            fh.write("ial\nnext\n")
        assert list(t.poll()) == ["partial", "next"]
        # truncation resets
        with p.open("w") as fh:
            fh.write("fresh1\n")
        assert list(t.poll()) == ["fresh1"]


def test_missing_file_tolerated():
    t = FileTail(Path("/nonexistent/x.log"))
    assert list(t.poll()) == []