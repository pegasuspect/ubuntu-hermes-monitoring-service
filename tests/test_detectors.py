import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from hermes_sentinel.sources.hermes_logs import HermesLogDetector, LINE_RE  # noqa: E402
from hermes_sentinel.sources.gateway_state import GatewayStateDetector  # noqa: E402
from hermes_sentinel.sources.integrity import IntegrityDetector  # noqa: E402
from hermes_sentinel.sources.sessions import SessionsDetector  # noqa: E402
from hermes_sentinel.sources.system_auth import SystemAuthDetector  # noqa: E402

import tempfile  # noqa: E402


def mk_hermes(td):
    hh = Path(td) / ".hermes"
    (hh / "logs").mkdir(parents=True)
    (hh / "state").mkdir()
    (hh / "sessions").mkdir()
    return hh


def test_line_re_matches_real_format():
    line = ("2026-10-06 12:25:34,619 ERROR gateway.platforms.signal: Signal: "
            "cannot reach signal-cli at http://localhost:8099: All connection "
            "attempts failed")
    m = LINE_RE.match(line)
    assert m and m.group("level") == "ERROR"
    assert m.group("logger") == "gateway.platforms.signal"


def test_unauthorized_message_detected(tmp_path):
    hh = mk_hermes(tmp_path)
    log = hh / "logs" / "agent.log"
    log.write_text("")
    det = HermesLogDetector("hermes-logs", hh, allowed_users=["+15555550100"])
    det.poll()  # baseline
    log.write_text(
        "2026-10-06 12:26:10,000 WARNING gateway.run: Dropping message from "
        "unauthorized user in active session: user=+15550001111 (Stranger), "
        "platform=signal, session=agent:main:signal:dm:+15550001111\n")
    events = det.poll()
    assert len(events) == 1
    ev = events[0]
    assert ev.kind == "unauthorized-message"
    assert ev.severity.value == "critical"
    assert "+15550001111" in ev.detail


def test_respawn_storm_detected(tmp_path):
    hh = mk_hermes(tmp_path)
    log = hh / "logs" / "errors.log"
    log.write_text("")
    det = HermesLogDetector("hermes-logs", hh, allowed_users=["x"])
    det.poll()
    log.write_text(
        "2026-09-06 01:25:15,959 WARNING hermes_cli.gateway: Gateway "
        "(re)started 6 times in 120s — backing off 10s to break a respawn "
        "storm.\n")
    events = det.poll()
    assert len(events) == 1 and events[0].kind == "respawn-storm"


def test_signal_outage_streak(tmp_path):
    hh = mk_hermes(tmp_path)
    log = hh / "logs" / "agent.log"
    log.write_text("")
    det = HermesLogDetector("hermes-logs", hh, allowed_users=["x"],
                            signal_outage_critical_after=2)
    det.poll()
    line = ("2026-10-06 12:25:34,619 ERROR gateway.platforms.signal: Signal: "
            "cannot reach signal-cli at http://localhost:8099: x\n")
    with log.open("a") as fh:
        fh.write(line)
    e1 = det.poll()
    assert len(e1) == 1 and e1[0].severity.value == "warning"
    with log.open("a") as fh:
        fh.write(line + line)
    e3 = det.poll()
    assert len(e3) == 2 and all(e.severity.value == "critical" for e in e3)


def test_heartbeat_stale(tmp_path):
    hh = mk_hermes(tmp_path)
    import json
    old = time.time() - 1000
    hb = {"pid": 999999, "updated_at": _iso(old)}
    (hh / "state" / "gateway.heartbeat").write_text(json.dumps(hb))
    det = GatewayStateDetector("gw", hh, grace=0.0, stale_after=180.0)
    events = det.poll()
    # pid 999999 is dead -> critical dead-pid event wins
    assert len(events) == 1 and events[0].kind == "gateway-pid-dead"


def test_restart_storm_from_starts_log(tmp_path):
    hh = mk_hermes(tmp_path)
    starts = hh / "gateway-starts.log"
    now = time.time()
    starts.write_text("\n".join(str(now - 10) for _ in range(4)) + "\n")
    det = GatewayStateDetector("gw", hh, grace=0.0,
                               restart_window=300.0, restart_threshold=3)
    det.poll()  # baseline
    with starts.open("a") as fh:
        fh.write(f"{now}\n")
    events = det.poll()
    assert len(events) == 1
    assert events[0].kind == "restart-storm"
    assert events[0].severity.value == "warning"


def test_integrity_change(tmp_path):
    hh = mk_hermes(tmp_path)
    target = hh / "auth.json"
    target.write_text('{"a": 1}')
    det = IntegrityDetector("integ", hh, files=[str(target)])
    assert det.poll() == []  # baseline
    time.sleep(0.01)
    target.write_text('{"a": 2}')  # mtime changes
    events = det.poll()
    assert len(events) == 1 and events[0].kind == "file-modified"
    # deletion
    target.unlink()
    events = det.poll()
    assert len(events) == 1 and events[0].kind == "file-deleted"


def test_sessions_unknown_sender(tmp_path):
    import json
    hh = mk_hermes(tmp_path)
    sessions = hh / "sessions" / "sessions.json"
    sessions.write_text(json.dumps({
        "_README": "x",
        "agent:main:signal:dm:+15555550100": {
            "session_id": "s1", "platform": "signal", "chat_type": "dm",
            "display_name": "Me", "origin": {"user_id": "+15555550100", "user_name": "Me"},
        }
    }))
    det = SessionsDetector("sess", hh, allowed_users=["+15555550100"])
    assert det.poll() == []  # baseline adopts existing
    sessions.write_text(json.dumps({
        "_README": "x",
        "agent:main:signal:dm:+15555550100": {
            "session_id": "s1", "platform": "signal", "chat_type": "dm",
            "display_name": "Me", "origin": {"user_id": "+15555550100", "user_name": "Me"},
        },
        "agent:main:signal:dm:+15559998888": {
            "session_id": "s2", "platform": "signal", "chat_type": "dm",
            "display_name": "Stranger", "origin": {"user_id": "+15559998888", "user_name": "Stranger"},
        }
    }))
    events = det.poll()
    assert len(events) == 1
    assert events[0].kind == "unknown-dm-session"
    assert events[0].severity.value == "warning"


def test_authlog_bruteforce(tmp_path):
    hh = mk_hermes(tmp_path)
    authlog = Path(tmp_path) / "auth.log"
    authlog.write_text("")
    det = SystemAuthDetector("auth", hh, auth_log=str(authlog),
                             brute_force_window=300.0, brute_force_threshold=5)
    det.poll()  # baseline
    import time as t
    now = t.strftime("%b %e %H:%M:%S")
    lines = [
        f"{now} host sshd[123]: Failed password for root from 203.0.113.9 port 4000 ssh2",
        f"{now} host sshd[124]: Invalid user admin from 203.0.113.9 port 4001",
        f"{now} host sshd[125]: Failed password for invalid user admin from 203.0.113.9 port 4002 ssh2",
        f"{now} host sshd[126]: Failed password for root from 203.0.113.9 port 4003 ssh2",
        f"{now} host sshd[127]: Failed password for root from 203.0.113.9 port 4004 ssh2",
        f"{now} host sshd[128]: Failed password for root from 203.0.113.9 port 4005 ssh2",
    ]
    with authlog.open("a") as fh:
        fh.write("\n".join(lines) + "\n")
    events = det.poll()
    kinds = {e.kind for e in events}
    assert "ssh-bruteforce" in kinds
    bf = [e for e in events if e.kind == "ssh-bruteforce"][0]
    assert bf.severity.value == "warning"
    assert "203.0.113.9" in bf.detail


def test_authlog_ssh_login_and_newuser(tmp_path):
    hh = mk_hermes(tmp_path)
    authlog = Path(tmp_path) / "auth.log"
    authlog.write_text("")
    det = SystemAuthDetector("auth", hh, auth_log=str(authlog))
    det.poll()
    import time as t
    now = t.strftime("%b %e %H:%M:%S")
    with authlog.open("a") as fh:
        fh.write(f"{now} host sshd[1]: Accepted publickey for alice from 192.168.1.5 port 22 ssh2\n")
        fh.write(f"{now} host useradd[2]: new user: name=backdoor, UID=1002, GID=1002\n")
    events = det.poll()
    kinds = {e.kind for e in events}
    assert "ssh-login" in kinds
    assert "user-created" in kinds
    uc = [e for e in events if e.kind == "user-created"][0]
    assert uc.severity.value == "critical"


def _iso(epoch: float) -> str:
    from datetime import datetime
    return datetime.fromtimestamp(epoch).isoformat()