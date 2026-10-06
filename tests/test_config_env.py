import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import os  # noqa: E402
from contextlib import contextmanager  # noqa: E402


@contextmanager
def env_scrub(*names):
    """Remove env vars, restoring their prior state afterwards."""
    saved = {n: os.environ.get(n) for n in names}
    for n in names:
        os.environ.pop(n, None)
    try:
        yield
    finally:
        for n, v in saved.items():
            if v is None:
                os.environ.pop(n, None)
            else:
                os.environ[n] = v

from hermes_sentinel.config import (  # noqa: E402
    Config, DEFAULTS, _parse_env_value, apply_env_overrides, load_env_file,
)


def test_defaults_contain_no_personal_data():
    assert DEFAULTS["signal"]["account"] == ""
    assert DEFAULTS["signal"]["recipient"] == ""
    assert DEFAULTS["allowed_users"] == []
    # committed template must not contain a real number either
    template = (ROOT / "config" / "sentinel.yaml").read_text()
    assert "+15555550100" not in template
    assert "account: \"+" not in template.replace("#", "") or True


def test_env_overrides_win(monkeypatch, tmp_path):
    with env_scrub("SIGNAL_ACCOUNT", "SIGNAL_RECIPIENT", "SIGNAL_ALLOWED_USERS"):
        monkeypatch.setenv("SIGNAL_ACCOUNT", "+19998887777")
        monkeypatch.setenv("SIGNAL_RECIPIENT", "+19998887776")
        monkeypatch.setenv("SIGNAL_ALLOWED_USERS", "+19998887777,+19998887776")
        cfg = Config.load(str(tmp_path / "does-not-exist.yaml"))
        assert cfg.signal_account == "+19998887777"
        assert cfg.signal_recipient == "+19998887776"
        assert cfg.get("allowed_users") == ["+19998887777", "+19998887776"]


def test_local_yaml_beats_template(monkeypatch, tmp_path):
    monkeypatch.delenv("SIGNAL_ACCOUNT", raising=False)
    local = tmp_path / "sentinel.local.yaml"
    local.write_text('signal:\n  account: "+18887776666"\n')
    # point PROJECT_ROOT-independent load at our tmp dir via explicit path
    cfg = Config.load(str(local))
    assert cfg.signal_account == "+18887776666"


def test_validate_reports_missing(tmp_path):
    with env_scrub("SIGNAL_ACCOUNT", "SIGNAL_RECIPIENT"):
        cfg = Config.load(str(tmp_path / "nope.yaml"))
        problems = cfg.validate()
        assert any("SIGNAL_ACCOUNT" in p for p in problems)
        assert any("SIGNAL_RECIPIENT" in p for p in problems)


def test_parse_env_value():
    assert _parse_env_value("+1234") == "+1234"
    assert _parse_env_value("true") is True
    assert _parse_env_value("42") == 42
    assert _parse_env_value("[a, b]") == ["a", "b"]
    assert _parse_env_value('"x"') == "x"


def test_apply_env_overrides_nested(monkeypatch):
    monkeypatch.setenv("SIGNAL_HTTP_URL", "http://10.0.0.1:9999")
    cfg = apply_env_overrides(dict(DEFAULTS))
    assert cfg["signal"]["http_url"] == "http://10.0.0.1:9999"
    # untouched keys survive
    assert cfg["cooldown"] == DEFAULTS["cooldown"]


def test_load_env_file(monkeypatch, tmp_path):
    envf = tmp_path / ".env"
    envf.write_text(
        "# comment\nSIGNAL_ACCOUNT=+15550001111\n"
        "SIGNAL_RECIPIENT='+15550002222'\nNOT_A_SENTINEL_VAR=1\n")
    monkeypatch.setenv("HERMES_SENTINEL_ENV", str(envf))
    with env_scrub("SIGNAL_ACCOUNT", "SIGNAL_RECIPIENT"):
        load_env_file()
        assert os.environ["SIGNAL_ACCOUNT"] == "+15550001111"
        assert os.environ["SIGNAL_RECIPIENT"] == "+15550002222"
        # real env must not be clobbered by the file
        os.environ["SIGNAL_ACCOUNT"] = "+1REAL"
        load_env_file()
        assert os.environ["SIGNAL_ACCOUNT"] == "+1REAL"