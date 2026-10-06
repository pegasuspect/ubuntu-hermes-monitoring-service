"""CLI: run, test-signal, check, recent, reset."""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path

from . import __version__
from .config import Config
from .events import Event, Severity
from .ledger import Ledger, load_events_journal
from .monitor import Monitor
from .notifier import SignalNotifier
from .util import hostname


def cmd_run(args, config: Config) -> int:
    monitor = Monitor(config, dry_run=args.dry_run)
    monitor.setup_logging(verbose=args.verbose)
    monitor.start()
    return 0


def cmd_check(args, config: Config) -> int:
    ok = True
    print(f"hermes-sentinel v{__version__} on {hostname()}")
    print(f"config: {config.origin or 'defaults'}")
    for problem in config.validate():
        print(f"  MISSING {problem}")
        ok = False
    hermes = config.hermes_home
    print(f"hermes home: {hermes} {'OK' if hermes.is_dir() else 'MISSING'}")
    for rel in ("logs/agent.log", "logs/errors.log", "state/gateway.heartbeat",
                "gateway-starts.log", "sessions/sessions.json"):
        p = hermes / rel
        print(f"  {'OK     ' if p.exists() else 'MISSING'} {rel}")
    auth = Path(str(config.get("paths.auth_log", "/var/log/auth.log")))
    if auth.is_file():
        try:
            with auth.open("rb") as fh:
                fh.read(1)
            print(f"  OK      system auth log {auth}")
        except OSError:
            print(f"  DENIED  system auth log {auth} (journal fallback will be used)")
            ok = False
    else:
        print(f"  MISSING system auth log {auth} (journal fallback will be used)")
        ok = False
    notifier = SignalNotifier(config.signal_url, config.signal_account,
                              config.signal_recipient)
    if notifier.check():
        print(f"  OK      signal-cli daemon at {config.signal_url}")
    else:
        print(f"  DOWN    signal-cli daemon at {config.signal_url}")
        ok = False
    print(f"  state:  {config.state_file}")
    print(f"  alerts: {len(config.notify_on)} severity level(s): "
          f"{', '.join(config.notify_on)}")
    print("check:", "PASS" if ok else "WARN (service can run, but some "
          "sources unavailable)")
    return 0


def cmd_test_signal(args, config: Config) -> int:
    problems = config.validate()
    if problems and not args.dry_run:
        for p in problems:
            print(f"ERROR: {p}")
        return 1
    notifier = SignalNotifier(
        config.signal_url, config.signal_account,
        "" if args.dry_run else config.signal_recipient,
        timeout=float(config.get("signal.send_timeout", 15.0)))
    ev = Event(
        source="hermes-sentinel",
        kind="test",
        title="Test alert",
        severity=Severity.INFO,
        detail="If you can read this, hermes-sentinel can reach you.",
    )
    if args.dry_run:
        print(f"[dry-run] recipient={config.signal_recipient}")
        print(ev.render(hostname()))
        return 0
    ok, err = notifier.send_message(ev.render(hostname()))
    print("sent" if ok else f"FAILED: {err}")
    return 0 if ok else 1


def cmd_recent(args, config: Config) -> int:
    ledger = Ledger(config.state_file)
    rows = ledger.recent(limit=args.limit)
    if not rows:
        print("no tracked events yet")
        return 0
    for row in rows:
        when = time.strftime("%Y-%m-%d %H:%M:%S",
                             time.localtime(row.get("last_seen", 0)))
        print(f"{when}  x{row.get('count', 1):<3} {row.get('kind', '?'):<22} "
              f"{row.get('source', '?'):<20} {row.get('detail', '')[:80]}")
    return 0


def cmd_reset(args, config: Config) -> int:
    ledger = Ledger(config.state_file)
    ledger.reset(args.fingerprint)
    ledger.save()
    print("ledger cleared" if args.fingerprint is None
          else f"cleared {args.fingerprint}")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="hermes-sentinel",
        description="Signal-alerting security monitor for the Hermes agent")
    parser.add_argument("--config", "-c", help="path to sentinel.yaml")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command")

    p_run = sub.add_parser("run", help="run the monitor (foreground)")
    p_run.add_argument("--dry-run", action="store_true",
                       help="log alerts instead of sending Signal messages")
    p_run.add_argument("--verbose", "-v", action="store_true")
    p_run.set_defaults(func=cmd_run)

    p_check = sub.add_parser("check", help="verify data sources and connectivity")
    p_check.set_defaults(func=cmd_check)

    p_test = sub.add_parser("test-signal", help="send a test alert to Signal")
    p_test.add_argument("--dry-run", action="store_true")
    p_test.set_defaults(func=cmd_test_signal)

    p_recent = sub.add_parser("recent", help="show recently tracked events")
    p_recent.add_argument("--limit", "-n", type=int, default=20)
    p_recent.set_defaults(func=cmd_recent)

    p_reset = sub.add_parser("reset", help="clear dedup/cooldown ledger")
    p_reset.add_argument("--fingerprint", help="clear a single fingerprint")
    p_reset.set_defaults(func=cmd_reset)

    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        parser.print_help()
        return 2
    config = Config.load(args.config)
    return args.func(args, config)


if __name__ == "__main__":
    sys.exit(main())