import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from hermes_sentinel.events import Event, Severity  # noqa: E402
from hermes_sentinel.ledger import Ledger  # noqa: E402

import json  # noqa: E402
import tempfile  # noqa: E402


def make_ledger(tmpdir, cooldown=900.0, escalate_after=3):
    return Ledger(Path(tmpdir) / "state.json", cooldown=cooldown,
                  escalate_after=escalate_after)


def test_first_event_alerts():
    with tempfile.TemporaryDirectory() as td:
        led = make_ledger(td)
        ev = Event("t", "k", "T", Severity.WARNING, detail="d1")
        out = led.filter_new([ev])
        assert len(out) == 1 and out[0].severity == Severity.WARNING


def test_cooldown_suppresses_repeat():
    with tempfile.TemporaryDirectory() as td:
        led = make_ledger(td, cooldown=900.0)
        ev = Event("t", "k", "T", Severity.WARNING, detail="d1")
        assert len(led.filter_new([ev])) == 1
        # same fingerprint within cooldown -> suppressed
        assert led.filter_new([Event("t", "k", "T", Severity.WARNING, detail="d1")]) == []
        # different fingerprint -> passes
        assert len(led.filter_new([Event("t", "k", "T", Severity.WARNING, detail="d2")])) == 1


def test_escalation():
    with tempfile.TemporaryDirectory() as td:
        led = make_ledger(td, escalate_after=3)
        # first three observations: no escalation
        e1 = Event("t", "k", "T", Severity.WARNING, detail="d1")
        led.filter_new([e1])
        assert e1.severity == Severity.WARNING
        led.reset(e1.fingerprint)
        led.save()
        # simulate 2 prior occurrences by pre-seeding the ledger
        led2 = Ledger(Path(td) / "state.json", cooldown=0.0, escalate_after=3)
        led2._entries[e1.fingerprint] = {"count": 2, "first_seen": 0,
                                        "last_alerted": 0.0, "last_seen": 0.0}
        led2._dirty = True
        out = led2.filter_new([Event("t", "k", "T", Severity.WARNING, detail="d1")])
        assert out and out[0].severity == Severity.CRITICAL
        assert "x3" in out[0].title


def test_persistence_roundtrip():
    with tempfile.TemporaryDirectory() as td:
        led = make_ledger(td)
        led.filter_new([Event("t", "k", "T", Severity.WARNING, detail="d1")])
        led.save()
        led2 = make_ledger(td, cooldown=0.0)
        # cooldown 0 -> re-alert even after restart
        out = led2.filter_new([Event("t", "k", "T", Severity.WARNING, detail="d1")])
        assert len(out) == 1


def test_reset():
    with tempfile.TemporaryDirectory() as td:
        led = make_ledger(td)
        ev = Event("t", "k", "T", Severity.WARNING, detail="d1")
        led.filter_new([ev])
        led.reset(ev.fingerprint)
        led.save()
        led2 = make_ledger(td, cooldown=0.0)
        out = led2.filter_new([ev])
        assert len(out) == 1 and out[0].count if hasattr(out[0], "count") else True
        assert out[0].severity == Severity.WARNING  # count reset -> no escalation


def test_severity_weights():
    assert Severity.CRITICAL.weight > Severity.WARNING.weight > Severity.INFO.weight
    assert Severity.parse("Critical") == Severity.CRITICAL
    assert Severity.parse("bogus") == Severity.WARNING