import json
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import os  # noqa: E402

from hermes_sentinel.config import Config, _merge, _mini_yaml  # noqa: E402
from hermes_sentinel.events import Event, Severity  # noqa: E402
from hermes_sentinel.notifier import SignalNotifier, SignalSendError  # noqa: E402

_SENTINEL_ENV_VARS = [
    "SIGNAL_ACCOUNT", "SIGNAL_RECIPIENT", "SIGNAL_ALLOWED_USERS",
    "SIGNAL_HTTP_URL", "NOTIFY_ON", "AUTH_LOG_PATH",
]


@contextmanager
def _no_sentinel_env():
    """Isolate config tests from the real environment."""
    saved = {n: os.environ.get(n) for n in _SENTINEL_ENV_VARS}
    for n in _SENTINEL_ENV_VARS:
        os.environ.pop(n, None)
    try:
        yield
    finally:
        for n, v in saved.items():
            if v is None:
                os.environ.pop(n, None)
            else:
                os.environ[n] = v


def test_merge_nested():
    base = {"a": {"b": 1, "c": 2}, "d": 3}
    out = _merge(base, {"a": {"b": 9}, "e": 4})
    assert out == {"a": {"b": 9, "c": 2}, "d": 3, "e": 4}


def test_mini_yaml():
    text = """
# comment
poll_interval: 10.0
notify_on: [warning, critical]
signal:
  account: "+1123"
  retry: 2
flag: true
"""
    data = _mini_yaml(text)
    assert data["poll_interval"] == 10.0
    assert data["notify_on"] == ["warning", "critical"]
    assert data["signal"]["account"] == "+1123"
    assert data["signal"]["retry"] == 2
    assert data["flag"] is True


def test_config_load_explicit(tmp_path):
    cfg_path = tmp_path / "sentinel.yaml"
    cfg_path.write_text("cooldown: 60.0\nsignal:\n  account: '+1999'\n")
    with _no_sentinel_env():
        cfg = Config.load(str(cfg_path))
        assert cfg.get("cooldown") == 60.0
        assert cfg.signal_account == "+1999"
        # defaults still apply for unspecified keys
        assert cfg.get("escalate_after") == 3


def test_config_defaults():
    with _no_sentinel_env():
        cfg = Config.load("/nonexistent/path.yaml")
        assert cfg.get("poll_interval") == 10.0
        assert cfg.signal_url == "http://127.0.0.1:8099"
        assert cfg.notify_on == ["warning", "critical"]
        # placeholders, not personal data
        assert cfg.signal_account == ""
        assert cfg.signal_recipient == ""


def test_notifier_validate_result():
    ok, err = SignalNotifier._validate({"results": [{"type": "SUCCESS"}]})
    assert ok
    ok, err = SignalNotifier._validate({"results": [{"type": "UNREGISTERED_FAILURE"}]})
    assert not ok and "UNREGISTERED" in err
    ok, err = SignalNotifier._validate({"results": [{"success": False, "failure": {"name": "x"}}]})
    assert not ok
    ok, err = SignalNotifier._validate(None)
    assert ok


def test_notifier_send_message_via_fake_rpc(monkeypatch, tmp_path):
    sent = []

    class FakeResp:
        status = 200
        def read(self):
            return json.dumps({"jsonrpc": "2.0", "result": {"timestamp": 1}}).encode()
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout=None):
        sent.append(json.loads(req.data.decode()))
        return FakeResp()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    n = SignalNotifier("http://127.0.0.1:8999", "+1111", "+1222")
    ok, err = n.send_message("hello")
    assert ok and err is None
    payload = sent[0]
    assert payload["method"] == "send"
    assert payload["params"]["recipient"] == ["+1222"]
    assert payload["params"]["message"] == "hello"


def test_notifier_group_recipient(monkeypatch):
    sent = []

    class FakeResp:
        status = 200
        def read(self):
            return json.dumps({"result": {}}).encode()
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    monkeypatch.setattr("urllib.request.urlopen",
                        lambda req, timeout=None: (sent.append(json.loads(req.data.decode())), FakeResp())[1])
    n = SignalNotifier("http://x", "+1111", "group:abc123=")
    ok, _ = n.send_message("hi")
    assert ok
    assert sent[0]["params"]["groupId"] == "abc123="


def test_notifier_retries_on_error(monkeypatch):
    calls = {"n": 0}

    def failing(req, timeout=None):
        calls["n"] += 1
        raise OSError("connection refused")

    monkeypatch.setattr("urllib.request.urlopen", failing)
    n = SignalNotifier("http://x", "+1111", "+1222", retry=2, retry_backoff=0.0)
    ok, err = n.send_message("hi")
    assert not ok and "connection refused" in err
    assert calls["n"] == 3  # 1 + 2 retries


def test_notify_filters_by_severity():
    n = SignalNotifier("http://x", "+1", "+1")
    events = [
        Event("s", "i", "info event", Severity.INFO),
        Event("s", "w", "warn event", Severity.WARNING),
        Event("s", "c", "crit event", Severity.CRITICAL),
    ]
    sent, skipped, _ = n.notify(events, notify_on=["warning", "critical"])
    # INFO is filtered out below the floor (counts as skipped);
    # warn+crit are attempted but fail (no real daemon in this test)
    assert sent == 0 and skipped == 3

    # with info enabled, all three are attempted (and fail)
    sent2, skipped2, _ = n.notify(events, notify_on=["info"])
    assert sent2 == 0 and skipped2 == 3


def test_event_render():
    ev = Event("hermes.test", "k", "Title", Severity.CRITICAL, detail="the detail")
    text = ev.render("myhost")
    assert "CRITICAL" in text and "Title" in text
    assert "the detail" in text and "myhost" in text


def test_event_fingerprint_default():
    a = Event("s", "k", "t", Severity.INFO, detail="same")
    b = Event("s", "k", "t", Severity.INFO, detail="same")
    assert a.fingerprint == b.fingerprint
    c = Event("s", "k", "t", Severity.INFO, detail="other")
    assert a.fingerprint != c.fingerprint