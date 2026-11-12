"""Command line entry point, handy for one-off runs inside the container.

    python -m app.cli ingest            # all sources
    python -m app.cli ingest kev
    python -m app.cli backfill-epss 2026-10-01 2026-10-31
"""

import argparse
import sys
from datetime import date

from . import runner
from .config import get_settings
from .sources import SOURCES


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="fucmonitor")
    sub = parser.add_subparsers(dest="command", required=True)
    ingest = sub.add_parser("ingest", help="Download today's snapshot")
    ingest.add_argument("source", nargs="?", choices=sorted(SOURCES))
    backfill = sub.add_parser("backfill-epss", help="Download historical EPSS days")
    backfill.add_argument("start", type=date.fromisoformat)
    backfill.add_argument("end", type=date.fromisoformat)
    args = parser.parse_args(argv)

    settings = get_settings()
    failed = False
    if args.command == "ingest":
        for name in [args.source] if args.source else list(SOURCES):
            run = runner.run_source(settings, name, "cli")
            print(f"{name}: {run['status']} {run.get('snapshot_date') or ''} {run.get('message') or ''}")
            failed |= run["status"] != "success"
    else:
        have = set(SOURCES["epss"].snapshot_dates(settings))
        for n in range(args.start.toordinal(), args.end.toordinal() + 1):
            day = date.fromordinal(n)
            if day in have:
                continue
            run = runner.run_source(settings, "epss", "backfill", backfill_day=day)
            print(f"epss {day}: {run['status']} {run.get('message') or ''}")
            failed |= run["status"] != "success"
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
